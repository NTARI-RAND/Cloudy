package consumerapi

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/economy"
)

type registerRequest struct {
	PublicKey string `json:"public_key"` // hex ed25519 public key
	Signature string `json:"signature"`  // hex ed25519 signature over the register challenge, proving key possession
}

type registerResponse struct {
	AccountID string `json:"account_id"`
	MemberID  string `json:"member_id"`
}

// handleRegister registers a member's public key. It is self-authenticating:
// the caller proves possession of the private key by signing the register
// challenge, so no one can register a key that is not theirs. Registration is
// open (zero-cost) — the JFA onboarding stance — and idempotent: re-registering
// the same key returns the same ids.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	pub, ok := decodeKey(req.PublicKey)
	if !ok {
		writeErr(w, http.StatusBadRequest, "public_key must be a 32-byte hex ed25519 key")
		return
	}
	sig, ok := decodeSig(req.Signature)
	if !ok {
		writeErr(w, http.StatusBadRequest, "signature must be a 64-byte hex ed25519 signature")
		return
	}
	if !ed25519.Verify(pub, s.registerChallenge(pub), sig) {
		writeErr(w, http.StatusUnauthorized, "signature does not prove possession of this key")
		return
	}

	member := covenant.MemberIDFor(s.platform, pub)
	account := economy.AccountIDFor(s.platform, pub)

	// One key, two platform-scoped IDs, ONE owned copy in the shared registry:
	// the covenant and economy views resolve the same registered key.
	owned := append(ed25519.PublicKey(nil), pub...)
	s.mu.Lock()
	s.byMember[member] = owned
	s.byAccount[account] = owned
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, registerResponse{
		AccountID: hx(account[:]),
		MemberID:  string(member),
	})
}

type distributionDTO struct {
	// Counts per LBTAS level, keyed by the level's name — never averaged into a
	// score. Total is transaction volume, not a denominator.
	Counts map[string]int `json:"counts"`
	Total  int            `json:"total"`
}

type relationStandingDTO struct {
	Overall    distributionDTO            `json:"overall"`
	ByCategory map[string]distributionDTO `json:"by_category"`
	Harm       int                        `json:"harm"` // count of No Trust (-1); surfaced by name, never diluted
}

type standingResponse struct {
	MemberID string `json:"member_id"`
	// Relations types the standing: trade, adjudication-conduct, and
	// verdict-satisfaction are different relations with different base
	// rates, and this response deliberately provides NO cross-relation pool
	// — collapsing them would be the average committed across relations.
	Relations map[string]relationStandingDTO `json:"relations"`
}

func distToDTO(d covenant.Distribution) distributionDTO {
	counts := map[string]int{}
	for _, lvl := range covenant.Levels() {
		counts[lvl.String()] = d.Count(lvl)
	}
	return distributionDTO{Counts: counts, Total: d.Total()}
}

// handleStanding serves a member's LBTAS standing as distributions — per
// category, pooled overall, and the harm count — never a single score. Public:
// the covenant carries no PII and standing is world-readable (no information
// asymmetry). An unknown member yields an empty-but-valid standing.
func (s *Server) handleStanding(w http.ResponseWriter, r *http.Request) {
	member := covenant.MemberID(r.PathValue("id"))

	s.mu.Lock()
	standing, err := s.book.Standing(member)
	categories := s.categoryNames()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "reading standing")
		return
	}

	relations := map[string]relationStandingDTO{}
	for _, rel := range covenant.Relations() {
		rs := standing.Relation(rel)
		byCat := map[string]distributionDTO{}
		for _, name := range categories {
			byCat[name] = distToDTO(rs.Category(name))
		}
		relations[string(rel)] = relationStandingDTO{
			Overall:    distToDTO(rs.Overall()),
			ByCategory: byCat,
			Harm:       rs.Harm(),
		}
	}
	writeJSON(w, http.StatusOK, standingResponse{
		MemberID:  string(member),
		Relations: relations,
	})
}

// categoryNames returns the covenant's category vocabulary. Slice 1 uses the
// LBTAS defaults (the nil categories NewBook was given); surfaced here so the
// standing response enumerates them.
func (s *Server) categoryNames() []string {
	return []string{"reliability", "usability", "performance", "support"}
}
