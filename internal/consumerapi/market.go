package consumerapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/market"
	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

// handleCategories lists the hardware category allowlist (the node-class
// taxonomy). Public.
func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	cats := market.Categories()
	out := make([]string, len(cats))
	for i, c := range cats {
		out[i] = string(c)
	}
	writeJSON(w, http.StatusOK, map[string][]string{"categories": out})
}

type listingDTO struct {
	Platform     string `json:"platform"`
	Maker        string `json:"maker"`    // hex ed25519 public key
	Category     string `json:"category"` // must be an allowlisted hardware category
	Spec         string `json:"spec"`     // hex techtree claim id (must be an existing product_spec claim)
	AcceptFiat   bool   `json:"accept_fiat"`
	AcceptCredit bool   `json:"accept_member_credit"`
	Nonce        string `json:"nonce"` // hex 32
	ListedAtNs   int64  `json:"listed_at_ns"`
	Signature    string `json:"signature"` // hex ed25519
}

func (dto listingDTO) toListing() (market.Listing, bool) {
	maker, ok := decodeKey(dto.Maker)
	if !ok {
		return market.Listing{}, false
	}
	spec, ok := decodeHex32(dto.Spec)
	if !ok {
		return market.Listing{}, false
	}
	nonce, ok := decodeHex32(dto.Nonce)
	if !ok {
		return market.Listing{}, false
	}
	sig, ok := decodeSig(dto.Signature)
	if !ok {
		return market.Listing{}, false
	}
	return market.Listing{
		Platform:  dto.Platform,
		Maker:     maker,
		Category:  market.Category(dto.Category),
		Spec:      market.SpecRef(spec),
		Rails:     market.AcceptedRails{Fiat: dto.AcceptFiat, MemberCredit: dto.AcceptCredit},
		Nonce:     nonce,
		ListedAt:  time.Unix(0, dto.ListedAtNs).UTC(),
		Signature: sig,
	}, true
}

// handleCreateListing ingests a client-signed listing. Beyond the maker
// signature and category allowlist (enforced by market.Listing), it requires
// the Spec to be an existing techtree claim of Kind product_spec authored by
// the same maker — so a listing always points at a real, contestable product
// claim, and a maker cannot list against someone else's spec.
func (s *Server) handleCreateListing(w http.ResponseWriter, r *http.Request) {
	var dto listingDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	l, ok := dto.toListing()
	if !ok {
		writeErr(w, http.StatusBadRequest, "malformed listing fields")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registered(l.Maker) {
		writeErr(w, http.StatusUnauthorized, "maker is not a registered member")
		return
	}
	// The spec must be an anchored product_spec claim, authored by this maker.
	specClaim, ok := s.tree.Claim(techtree.ClaimID(l.Spec))
	if !ok {
		writeErr(w, http.StatusConflict, "spec must reference an anchored product-spec claim")
		return
	}
	if specClaim.Kind != techtree.KindProductSpec {
		writeErr(w, http.StatusConflict, "spec claim must be of kind product_spec")
		return
	}
	if !specClaim.Claimant.Equal(l.Maker) {
		writeErr(w, http.StatusConflict, "a listing's spec claim must be authored by the maker")
		return
	}
	id, err := s.catalog.AddListing(l)
	if err != nil {
		writeErr(w, listingStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"listing_id": hex.EncodeToString(id[:])})
}

func listingStatus(err error) int {
	switch {
	case errors.Is(err, market.ErrDuplicate):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

type listingView struct {
	ListingID    string `json:"listing_id"`
	Platform     string `json:"platform"`
	Maker        string `json:"maker"`
	Category     string `json:"category"`
	Spec         string `json:"spec"`
	AcceptFiat   bool   `json:"accept_fiat"`
	AcceptCredit bool   `json:"accept_member_credit"`
	ListedAt     string `json:"listed_at"`
	SalesCount   int    `json:"sales_count"` // number of recorded exchanges (provenance depth)
}

func (s *Server) listingViewLocked(id market.ListingID, l market.Listing) listingView {
	return listingView{
		ListingID:    hex.EncodeToString(id[:]),
		Platform:     l.Platform,
		Maker:        hx(l.Maker),
		Category:     string(l.Category),
		Spec:         hex.EncodeToString(l.Spec[:]),
		AcceptFiat:   l.Rails.Fiat,
		AcceptCredit: l.Rails.MemberCredit,
		ListedAt:     l.ListedAt.UTC().Format(time.RFC3339Nano),
		SalesCount:   len(s.catalog.SalesOf(id)),
	}
}

// handleBrowseListings lists listings in a category (query ?category=), in
// append order — never ranked or promoted. Public.
func (s *Server) handleBrowseListings(w http.ResponseWriter, r *http.Request) {
	cat := market.Category(r.URL.Query().Get("category"))
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := s.catalog.ByCategory(cat)
	out := make([]listingView, 0, len(ids))
	for _, id := range ids {
		l, ok := s.catalog.Listing(id)
		if !ok {
			continue
		}
		out = append(out, s.listingViewLocked(id, l))
	}
	writeJSON(w, http.StatusOK, map[string][]listingView{"listings": out})
}

// handleGetListing serves one listing. Public.
func (s *Server) handleGetListing(w http.ResponseWriter, r *http.Request) {
	idHex := r.PathValue("id")
	idBytes, err := hex.DecodeString(idHex)
	if err != nil || len(idBytes) != 32 {
		writeErr(w, http.StatusBadRequest, "listing id must be 32-byte hex")
		return
	}
	var id market.ListingID
	copy(id[:], idBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.catalog.Listing(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "listing not found")
		return
	}
	writeJSON(w, http.StatusOK, s.listingViewLocked(id, l))
}
