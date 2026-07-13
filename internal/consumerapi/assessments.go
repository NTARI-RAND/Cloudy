package consumerapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
)

type assessmentRequest struct {
	Assessor    string `json:"assessor"`               // MemberID of the assessing member; their key signs
	Subject     string `json:"subject"`                // MemberID whose standing this shapes
	Exchange    string `json:"exchange"`               // hex leaf ID of the sealed dialog both took part in
	Category    string `json:"category"`               // one of the Book's closed vocabulary
	Level       int8   `json:"level"`                  // LBTAS level, -1 (No Trust) .. +4
	CommentHash string `json:"comment_hash,omitempty"` // hex SHA-256 of the member-local justification; REQUIRED at No Trust
	IssuedAt    string `json:"issued_at"`
	Signature   string `json:"signature"` // hex ed25519 by the assessor over the canonical bytes
}

// handleRecordAssessment admits one member-signed LBTAS assessment. The Book
// is the only admission path and re-verifies everything: the assessor's
// signature against the directory, the anchor (the named exchange is a sealed
// dialog between exactly these two members — recAnchors joins it to the
// operator's Drops log), the closed category vocabulary, and the No-Trust
// comment-hash rule. The server adds nothing and can forge nothing.
//
// What is deliberately absent, per the covenant invariants: any endpoint that
// averages, ranks, or scores. Standing is served as distributions only
// (GET /api/v1/members/{id}/standing) and a harm stays visible beside the
// volume permanently.
func (s *Server) handleRecordAssessment(w http.ResponseWriter, r *http.Request) {
	var req assessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	exchange, ok := decodeHex32(req.Exchange)
	if !ok {
		writeErr(w, http.StatusBadRequest, "exchange must be a 32-byte hex leaf ID")
		return
	}
	var commentHash [32]byte
	if req.CommentHash != "" {
		if commentHash, ok = decodeHex32(req.CommentHash); !ok {
			writeErr(w, http.StatusBadRequest, "comment_hash must be a 32-byte hex digest when present")
			return
		}
	}
	issuedAt, ok := parseUTC(req.IssuedAt)
	if !ok {
		writeErr(w, http.StatusBadRequest, "issued_at must be RFC3339")
		return
	}
	sig, ok := decodeSig(req.Signature)
	if !ok {
		writeErr(w, http.StatusBadRequest, "signature must be a 64-byte hex signature")
		return
	}
	a := covenant.Assessment{
		Assessor:    covenant.MemberID(req.Assessor),
		Subject:     covenant.MemberID(req.Subject),
		Exchange:    covenant.ExchangeRef(exchange),
		Category:    req.Category,
		Level:       covenant.Level(req.Level),
		CommentHash: commentHash,
		IssuedAt:    issuedAt,
		Signature:   sig,
	}
	s.mu.Lock()
	err := s.book.Record(a)
	s.mu.Unlock()
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
	case errors.Is(err, covenant.ErrDuplicate):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}
