package consumerapi

import (
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

// signedClaimExport is deliberately separate from both claimView and claimDTO:
// it carries every signed field, but has no member-local narrative fields.
// Nanoseconds use a decimal string so JSON clients do not round an int64 through
// a floating-point number before reconstructing the signed instant.
type signedClaimExport struct {
	ClaimID      string `json:"claim_id"`
	Platform     string `json:"platform"`
	Claimant     string `json:"claimant"`
	Kind         string `json:"kind"`
	InputsHash   string `json:"inputs_hash"`
	MethodHash   string `json:"method_hash"`
	ResultHash   string `json:"result_hash"`
	Nonce        string `json:"nonce"`
	AssertedAtNS string `json:"asserted_at_ns"`
	Signature    string `json:"signature"`
}

// handleExportClaim is a public structural read, like the existing claim view.
// A valid signature proves authorship and unchanged bytes, never truth or an
// independent witness. No Locker content or server/member private key is read.
func (s *Server) handleExportClaim(w http.ResponseWriter, r *http.Request) {
	rawID, err := hex.DecodeString(r.PathValue("id"))
	if err != nil || len(rawID) != 32 {
		writeErr(w, http.StatusBadRequest, "claim id must be 32-byte hex")
		return
	}
	var id techtree.ClaimID
	copy(id[:], rawID)
	s.mu.Lock()
	claim, ok := s.tree.Claim(id) // Tree.Claim returns an owned defensive copy.
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "claim not found")
		return
	}
	idHex := hex.EncodeToString(id[:])
	export := signedClaimExport{
		ClaimID: idHex, Platform: claim.Platform, Claimant: hex.EncodeToString(claim.Claimant),
		Kind: string(claim.Kind), InputsHash: hex.EncodeToString(claim.InputsHash[:]),
		MethodHash: hex.EncodeToString(claim.MethodHash[:]), ResultHash: hex.EncodeToString(claim.ResultHash[:]),
		Nonce: hex.EncodeToString(claim.Nonce[:]), AssertedAtNS: strconv.FormatInt(claim.AssertedAt.UnixNano(), 10),
		Signature: hex.EncodeToString(claim.Signature),
	}
	w.Header().Set("Content-Disposition", `attachment; filename="claim-`+idHex+`.json"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(w, http.StatusOK, export)
}
