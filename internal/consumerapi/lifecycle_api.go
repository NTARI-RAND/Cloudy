package consumerapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/record"
)

// handleLifecycleCheckpoints serves the operator's signed checkpoint over its
// claim-LIFECYCLE log — the "witnessed as it happens" half of Part IV. Like
// the dialog checkpoint surface it carries the honest stand-in label until
// two or more independent witnesses countersign (Phase-3 federation).
func (s *Server) handleLifecycleCheckpoints(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cp := s.lifeLog.Checkpoint(time.Now().UTC())
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

type transitionView struct {
	Seq      uint64 `json:"seq"`
	Kind     string `json:"kind"` // filed | adjudicated | resolved | sealed
	Artifact string `json:"artifact"`
	Exchange string `json:"exchange"`
	At       string `json:"at"`
}

type lifecycleClaimResponse struct {
	ClaimID     string           `json:"claim_id"`
	State       string           `json:"state"`
	FiledAt     string           `json:"filed_at,omitempty"`
	Transitions []transitionView `json:"transitions"`
	// Dwell is deliberately NOT computed here: an unresolved claim's age is
	// a readable fact the reader derives from filed_at; the surface renders
	// facts, never verdicts (flag-not-finding discipline).
}

// handleLifecycleClaim serves one claim's transition history — structural
// facts only: kinds, digests, references, instants. The narrative stays
// member-local; the reader may compute dwell but is handed no judgment.
func (s *Server) handleLifecycleClaim(w http.ResponseWriter, r *http.Request) {
	id, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "id must be a 32-byte hex claim ID")
		return
	}
	claim := record.Hash(id)
	s.mu.Lock()
	seqs := s.lifeLog.Claim(claim)
	state, seen := s.lifeLog.State(claim)
	views := make([]transitionView, 0, len(seqs))
	var filedAt string
	for _, seq := range seqs {
		tr, err := s.lifeStore.At(seq)
		if err != nil {
			continue
		}
		v := transitionView{
			Seq:      seq,
			Kind:     tr.Kind.String(),
			Artifact: hx(tr.Artifact[:]),
			Exchange: hx(tr.Exchange[:]),
			At:       tr.At.UTC().Format(time.RFC3339Nano),
		}
		if tr.Kind == record.KindFiled {
			filedAt = v.At
		}
		views = append(views, v)
	}
	s.mu.Unlock()
	if !seen {
		writeErr(w, http.StatusNotFound, "no lifecycle transitions for this claim")
		return
	}
	writeJSON(w, http.StatusOK, lifecycleClaimResponse{
		ClaimID:     r.PathValue("id"),
		State:       state.String(),
		FiledAt:     filedAt,
		Transitions: views,
	})
}

type consistencyResponse struct {
	From  uint64   `json:"from"`
	Size  uint64   `json:"size"`
	Proof []string `json:"proof"` // RFC-6962 consistency proof hashes
}

// handleDropsConsistency serves the extension evidence a witness needs
// before countersigning a newer dialog-log checkpoint: the consistency
// proof from its last-seen size to the current tree.
func (s *Server) handleDropsConsistency(w http.ResponseWriter, r *http.Request) {
	s.serveConsistency(w, r, func(from uint64) ([]record.Hash, uint64, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		proof, err := s.opLog.ProveConsistency(from)
		return proof, s.opLog.Checkpoint(time.Now().UTC()).Size, err
	})
}

// handleLifecycleConsistency is the lifecycle-log twin.
func (s *Server) handleLifecycleConsistency(w http.ResponseWriter, r *http.Request) {
	s.serveConsistency(w, r, func(from uint64) ([]record.Hash, uint64, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		proof, err := s.lifeLog.ProveConsistency(from)
		return proof, s.lifeLog.Checkpoint(time.Now().UTC()).Size, err
	})
}

func (s *Server) serveConsistency(w http.ResponseWriter, r *http.Request, prove func(uint64) ([]record.Hash, uint64, error)) {
	var from uint64
	if q := r.URL.Query().Get("from"); q != "" {
		if _, err := fmt.Sscanf(q, "%d", &from); err != nil {
			writeErr(w, http.StatusBadRequest, "from must be a non-negative integer")
			return
		}
	}
	proof, size, err := prove(from)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out := consistencyResponse{From: from, Size: size, Proof: make([]string, len(proof))}
	for i, h := range proof {
		out.Proof[i] = hx(h[:])
	}
	writeJSON(w, http.StatusOK, out)
}

type proofResponse struct {
	ID         string             `json:"id"`
	Seq        uint64             `json:"seq"`
	Path       []string           `json:"path"` // sibling hashes, leaf-adjacent first
	Checkpoint checkpointResponse `json:"checkpoint"`
}

// handleDropProof serves the RFC-6962 inclusion proof for one sealed dialog
// under a fresh signed checkpoint — everything a member needs to verify,
// offline, that their covenant is in the log: ~log2(size) hashes, feasible
// on an entry-level device however large the log grows.
func (s *Server) handleDropProof(w http.ResponseWriter, r *http.Request) {
	id, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "id must be a 32-byte hex leaf ID")
		return
	}
	s.mu.Lock()
	seq, found := s.index[record.Hash(id)]
	var p record.Proof
	var cp record.Checkpoint
	var err error
	if found {
		p, err = s.opLog.Prove(seq)
		cp = s.opLog.Checkpoint(time.Now().UTC())
		cp.Sign(s.operatorPriv)
	}
	s.mu.Unlock()
	if !found || err != nil {
		writeErr(w, http.StatusNotFound, "no entry with this leaf ID")
		return
	}
	path := make([]string, len(p.Path))
	for i, h := range p.Path {
		path[i] = hx(h[:])
	}
	wc := record.WitnessedCheckpoint{Checkpoint: cp}
	writeJSON(w, http.StatusOK, proofResponse{
		ID:   r.PathValue("id"),
		Seq:  p.Seq,
		Path: path,
		Checkpoint: checkpointResponse{
			Log:               hx(cp.Log[:]),
			Size:              cp.Size,
			Head:              hx(cp.Head[:]),
			IssuedAt:          cp.IssuedAt.UTC().Format(time.RFC3339Nano),
			Signature:         hx(cp.Signature),
			Countersignatures: []string{},
			StandIn:           wc.StandIn(s.operatorPub),
		},
	})
}
