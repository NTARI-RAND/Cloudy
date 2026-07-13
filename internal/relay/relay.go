// Package relay is the witness relay: it schedules nothing it decides,
// relays checkpoints and filings, caches countersignatures, and serves the
// assembled WitnessedCheckpoint bundles. Its non-authority is structural
// and load-bearing (the architecture's witness-relay rule):
//
//   - it MUST NOT decide which witnesses count: it caches every
//     structurally valid countersignature and serves them all; readers
//     apply their own independence checks (WitnessedCheckpoint.Verify and
//     StandIn do exactly that);
//   - it MUST NOT decide which checkpoint is official: it caches what
//     operators publish, keyed by log, keeping only monotonic growth per
//     log (a relay that let a log's size run backward would be a rollback
//     amplifier, so it refuses regressions — refusing to UNPUBLISH is not
//     authority);
//   - it MUST NOT gate settlement: nothing consults the relay to decide
//     anything; and
//   - everything it does must remain possible without it: operators serve
//     their own checkpoints, witnesses can poll operators directly, and
//     filers can lodge commitments at any witness intake directly. The
//     relay is convenience topology, not a dependency.
//
// For filings the relay only FORWARDS: the one witness write (claim
// creation) happens at witness intakes; the relay fans a commitment out to
// the configured intake URLs and returns whatever receipts come back. It
// holds no intake key and can mint no receipt.
package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// CheckpointMsg is the wire form of a checkpoint plus its countersignatures.
// All fields are hex strings; the relay treats them as opaque beyond shape.
type CheckpointMsg struct {
	Log       string `json:"log"`
	Size      uint64 `json:"size"`
	Head      string `json:"head"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
	// Operator is the operator's public key (hex) — carried so witnesses
	// polling the relay know what to verify against; the relay itself
	// never verifies trust, only shape.
	Operator string `json:"operator"`
	// Kind names which of the operator's logs this checkpoint commits
	// ("dialog" or "lifecycle"); the log id already binds it
	// cryptographically, the kind is legibility for pollers.
	Kind string `json:"kind"`
	// ConsistencyFrom/Proof carry the operator-supplied extension evidence
	// from the previous published size, so witnesses can verify without a
	// second round trip. A witness MAY ignore this and fetch its own.
	ConsistencyFrom  uint64   `json:"consistency_from"`
	ConsistencyProof []string `json:"consistency_proof"`
}

// CountersigMsg is one witness countersignature over the checkpoint the
// relay currently caches for a log at a given size.
type CountersigMsg struct {
	Log       string `json:"log"`
	Size      uint64 `json:"size"`
	Witness   string `json:"witness"`
	Signature string `json:"signature"`
}

// BundleMsg is what readers get: the cached checkpoint and every cached
// countersignature for it. The relay does not rank, filter, or count them.
type BundleMsg struct {
	Checkpoint        CheckpointMsg   `json:"checkpoint"`
	Countersignatures []CountersigMsg `json:"countersignatures"`
}

type logState struct {
	cp     CheckpointMsg
	cosign map[string]CountersigMsg // witness hex -> countersig for cp.Size
}

// Relay is the in-memory relay. Durability is a deployment concern; the
// relay's cache is reconstructible from operators and witnesses by design.
type Relay struct {
	mu      sync.Mutex
	logs    map[string]*logState
	intakes []string // witness intake base URLs for filing fan-out
	client  *http.Client
}

// New returns a relay that fans filings out to the given witness intake
// URLs (each expecting POST {url}/v1/filings).
func New(intakes []string) *Relay {
	return &Relay{
		logs:    make(map[string]*logState),
		intakes: append([]string(nil), intakes...),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Handler mounts the relay's HTTP surface.
func (rl *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/logs/{log}/checkpoints", rl.handlePublish)
	mux.HandleFunc("POST /v1/logs/{log}/countersignatures", rl.handleCountersig)
	mux.HandleFunc("GET /v1/logs/{log}/checkpoints/latest", rl.handleLatest)
	mux.HandleFunc("GET /v1/logs", rl.handleLogs)
	mux.HandleFunc("POST /v1/filings", rl.handleFiling)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// handlePublish caches an operator-published checkpoint. Monotonic per log:
// a smaller-or-equal size does not replace a larger one (refusing rollback
// amplification), but is not an error — the operator may be re-publishing.
func (rl *Relay) handlePublish(w http.ResponseWriter, r *http.Request) {
	var msg CheckpointMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if msg.Log == "" || msg.Log != r.PathValue("log") {
		writeErr(w, http.StatusBadRequest, "log path and body disagree")
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	st, ok := rl.logs[msg.Log]
	if !ok || msg.Size > st.cp.Size {
		rl.logs[msg.Log] = &logState{cp: msg, cosign: make(map[string]CountersigMsg)}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cached"})
}

// handleCountersig caches a witness countersignature for the checkpoint the
// relay currently holds at that log and size. The relay verifies SHAPE only;
// readers verify signatures — the relay counting or vetting witnesses would
// be the authority it must not be.
func (rl *Relay) handleCountersig(w http.ResponseWriter, r *http.Request) {
	var msg CountersigMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if msg.Log != r.PathValue("log") {
		writeErr(w, http.StatusBadRequest, "log path and body disagree")
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	st, ok := rl.logs[msg.Log]
	if !ok || st.cp.Size != msg.Size {
		writeErr(w, http.StatusConflict, "no cached checkpoint at this size; poll latest and countersign that")
		return
	}
	st.cosign[msg.Witness] = msg
	writeJSON(w, http.StatusOK, map[string]string{"status": "cached"})
}

// handleLatest serves the cached bundle for one log.
func (rl *Relay) handleLatest(w http.ResponseWriter, r *http.Request) {
	rl.mu.Lock()
	st, ok := rl.logs[r.PathValue("log")]
	var bundle BundleMsg
	if ok {
		bundle.Checkpoint = st.cp
		for _, cs := range st.cosign {
			bundle.Countersignatures = append(bundle.Countersignatures, cs)
		}
	}
	rl.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "no checkpoint cached for this log")
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

// handleLogs lists the log ids the relay currently caches — discovery for
// witnesses that countersign everything they can see.
func (rl *Relay) handleLogs(w http.ResponseWriter, r *http.Request) {
	rl.mu.Lock()
	ids := make([]string, 0, len(rl.logs))
	for id := range rl.logs {
		ids = append(ids, id)
	}
	rl.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"logs": ids})
}

// handleFiling fans a filing commitment out to every configured witness
// intake and returns the receipts that came back. The relay holds no intake
// key: an empty intake list yields an empty receipt list, honestly.
func (rl *Relay) handleFiling(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "reading body")
		return
	}
	receipts := make([]json.RawMessage, 0, len(rl.intakes))
	failures := 0
	for _, base := range rl.intakes {
		resp, err := rl.client.Post(base+"/v1/filings", "application/json", bytes.NewReader(body))
		if err != nil {
			failures++
			continue
		}
		rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			failures++
			continue
		}
		receipts = append(receipts, json.RawMessage(rb))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"receipts": receipts,
		"intakes":  len(rl.intakes),
		"failures": failures,
	})
}
