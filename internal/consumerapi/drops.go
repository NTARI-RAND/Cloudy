package consumerapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/record"
)

// parseUTC parses an RFC3339 instant and normalizes it to UTC — the same
// normalization canon applies at signing time, so a client-signed artifact
// round-trips to identical canonical bytes.
func parseUTC(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

type dropsLogResponse struct {
	LogID       string `json:"log_id"`       // LogID of this operator's Drops log
	OperatorKey string `json:"operator_key"` // the operator's public key (checkpoint signer)
	Size        uint64 `json:"size"`         // entries committed so far
}

// handleDropsLog serves what a client needs before it can seal a dialog: the
// operator log's identity (inside every entry's signed bytes, so cross-log
// replay is dead) and the operator key checkpoints verify under. Public read.
func (s *Server) handleDropsLog(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cp := s.opLog.Checkpoint(time.Now().UTC())
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, dropsLogResponse{
		LogID:       hx(s.logID[:]),
		OperatorKey: hx(s.operatorPub),
		Size:        cp.Size,
	})
}

type dropRequest struct {
	Log          string `json:"log"`      // hex LogID; must be THIS operator's log
	Proposer     string `json:"proposer"` // hex ed25519 member key
	Acceptor     string `json:"acceptor"` // hex ed25519 member key
	Content      string `json:"content"`  // hex HashContent digest of the member-local narrative
	Corrects     string `json:"corrects"` // hex leaf ID of the entry corrected; empty or zero for a plain covenant
	Nonce        string `json:"nonce"`    // hex 32-byte client-drawn nonce
	SealedAt     string `json:"sealed_at"`
	ProposerSeal string `json:"proposer_seal"` // hex ed25519 seal over the entry's canonical bytes
	AcceptorSeal string `json:"acceptor_seal"`
}

type dropResponse struct {
	ID  string `json:"id"` // the entry's leaf hash: THE cross-layer exchange reference
	Seq uint64 `json:"seq"`
}

// handleAppendDrop accepts one fully dialog-sealed entry. The trust model is
// slice 1's: both seals are produced CLIENT-SIDE by the two members; the
// server holds no key that can produce a member seal, so its entire power is
// assigning the sequence number. Log.Append re-verifies everything (distinct
// well-formed keys, both seals over the same canonical bytes, log binding);
// this handler adds only the ingress policy that both parties are registered
// members — the composition root is the one place member IDs are minted, and
// an unregistered party's dialog could never anchor an assessment or dispute.
func (s *Server) handleAppendDrop(w http.ResponseWriter, r *http.Request) {
	var req dropRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	logID, ok := decodeHex32(req.Log)
	if !ok {
		writeErr(w, http.StatusBadRequest, "log must be a 32-byte hex LogID")
		return
	}
	if record.Hash(logID) != s.logID {
		writeErr(w, http.StatusBadRequest, "log does not name this operator's Drops log (GET /api/v1/drops/log)")
		return
	}
	proposer, ok := decodeKey(req.Proposer)
	if !ok {
		writeErr(w, http.StatusBadRequest, "proposer must be a 32-byte hex ed25519 key")
		return
	}
	acceptor, ok := decodeKey(req.Acceptor)
	if !ok {
		writeErr(w, http.StatusBadRequest, "acceptor must be a 32-byte hex ed25519 key")
		return
	}
	content, ok := decodeHex32(req.Content)
	if !ok {
		writeErr(w, http.StatusBadRequest, "content must be a 32-byte hex digest")
		return
	}
	var corrects [32]byte
	if req.Corrects != "" {
		if corrects, ok = decodeHex32(req.Corrects); !ok {
			writeErr(w, http.StatusBadRequest, "corrects must be a 32-byte hex leaf ID when present")
			return
		}
	}
	nonce, ok := decodeHex32(req.Nonce)
	if !ok {
		writeErr(w, http.StatusBadRequest, "nonce must be 32 hex bytes")
		return
	}
	sealedAt, ok := parseUTC(req.SealedAt)
	if !ok {
		writeErr(w, http.StatusBadRequest, "sealed_at must be RFC3339")
		return
	}
	pSeal, ok := decodeSig(req.ProposerSeal)
	if !ok {
		writeErr(w, http.StatusBadRequest, "proposer_seal must be a 64-byte hex signature")
		return
	}
	aSeal, ok := decodeSig(req.AcceptorSeal)
	if !ok {
		writeErr(w, http.StatusBadRequest, "acceptor_seal must be a 64-byte hex signature")
		return
	}

	e := record.Entry{
		Log:          record.Hash(logID),
		Proposer:     proposer,
		Acceptor:     acceptor,
		Content:      record.Hash(content),
		Corrects:     record.Hash(corrects),
		Nonce:        nonce,
		SealedAt:     sealedAt,
		ProposerSeal: pSeal,
		AcceptorSeal: aSeal,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registered(proposer) || !s.registered(acceptor) {
		writeErr(w, http.StatusBadRequest, "both parties must be registered members")
		return
	}
	seq, err := s.appendEntry(e)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := e.ID()
	writeJSON(w, http.StatusOK, dropResponse{ID: hx(id[:]), Seq: seq})
}

type dropView struct {
	ID           string `json:"id"`
	Seq          uint64 `json:"seq"`
	Log          string `json:"log"`
	Proposer     string `json:"proposer"`
	Acceptor     string `json:"acceptor"`
	Content      string `json:"content"`
	Corrects     string `json:"corrects,omitempty"`
	SealedAt     string `json:"sealed_at"`
	ProposerSeal string `json:"proposer_seal"`
	AcceptorSeal string `json:"acceptor_seal"`
}

// handleGetDrop serves one sealed entry by its leaf ID. Public read: the
// commons carries keys, hashes, and instants — no PII — so there is nothing
// to gate. The member-local narrative behind Content is NOT here and never
// will be; it lives in the erasable Locker on the member's own device.
func (s *Server) handleGetDrop(w http.ResponseWriter, r *http.Request) {
	id, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "id must be a 32-byte hex leaf ID")
		return
	}
	s.mu.Lock()
	seq, found := s.index[record.Hash(id)]
	var e record.Entry
	var err error
	if found {
		e, err = s.recStore.At(seq)
	}
	s.mu.Unlock()
	if !found || err != nil {
		writeErr(w, http.StatusNotFound, "no entry with this leaf ID")
		return
	}
	v := dropView{
		ID:           hx(id[:]),
		Seq:          seq,
		Log:          hx(e.Log[:]),
		Proposer:     hx(e.Proposer),
		Acceptor:     hx(e.Acceptor),
		Content:      hx(e.Content[:]),
		SealedAt:     e.SealedAt.UTC().Format(time.RFC3339Nano),
		ProposerSeal: hx(e.ProposerSeal),
		AcceptorSeal: hx(e.AcceptorSeal),
	}
	var zero record.Hash
	if e.Corrects != zero {
		v.Corrects = hx(e.Corrects[:])
	}
	writeJSON(w, http.StatusOK, v)
}

type checkpointResponse struct {
	Log               string   `json:"log"`
	Size              uint64   `json:"size"`
	Head              string   `json:"head"`
	IssuedAt          string   `json:"issued_at"`
	Signature         string   `json:"signature"` // operator's; verify against operator_key from /drops/log
	Countersignatures []string `json:"countersignatures"`
	// StandIn is the honest label the record layer REQUIRES a surface to carry:
	// true whenever fewer than two verified, operator-independent witnesses
	// have countersigned. A single-witness (or zero-witness) deployment must
	// present itself as the stand-in it is, never as federation.
	StandIn bool `json:"stand_in"`
}

// handleDropsCheckpoints serves the operator's current signed checkpoint as
// the publishable witnessed unit. Slice 2 runs with NO independent witnesses,
// so Countersignatures is empty and StandIn is true — the label is the API
// contract, not a debug field. Independent witnesses federate by appending
// countersignatures (Phase 3); nothing about this surface changes when they do.
func (s *Server) handleDropsCheckpoints(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cp := s.opLog.Checkpoint(time.Now().UTC())
	cp.Sign(s.operatorPriv)
	s.mu.Unlock()
	wc := record.WitnessedCheckpoint{Checkpoint: cp}
	writeJSON(w, http.StatusOK, checkpointResponse{
		Log:               hx(cp.Log[:]),
		Size:              cp.Size,
		Head:              hx(cp.Head[:]),
		IssuedAt:          cp.IssuedAt.UTC().Format(time.RFC3339Nano),
		Signature:         hx(cp.Signature),
		Countersignatures: []string{},
		StandIn:           wc.StandIn(s.operatorPub),
	})
}
