// Package consumerapi is Cloudy's member-facing JSON API — the surface the
// React Native app talks to, and the first member-facing ingress the headless
// composition root (cmd/cloudy) said did not yet exist. It is slice 1:
// onboarding, the Technology Tree (techtree), and the hardware Market. Economy
// spends, disputes, settlement, contribution control, and storage are later
// slices.
//
// Trust model (the load-bearing decision, from the Phase-1 design §7.1):
// member keys NEVER leave the member's device. Every member-authored artifact —
// a claim, a reference, a listing — is signed CLIENT-SIDE and arrives here
// already sealed; the server VALIDATES (signature + invariants), stores, and
// routes the member-local narrative to the erasable Locker. The server holds no
// member private key and mints nothing a member could forge.
//
// Reads are public: the commons (claims, listings, standing) carries no PII and
// is world-readable by the JFA "no information asymmetry" principle, so GET
// endpoints need no auth. Writes are authenticated by the embedded artifact
// signature itself — a claim is accepted only if it verifies under a registered
// member key — so slice 1 needs no session tokens; those are a later refinement
// for rate-limiting and non-artifact actions.
//
// Slice 1 uses in-memory stores and an ephemeral operator key, exactly like
// cmd/cloudy: it proves the surface end to end without pretending to be a
// durable deployment. Durable persistence and the record witnessing are the
// named follow-ups.
package consumerapi

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/market"
	"github.com/NTARI-RAND/Cloudy/internal/record"
	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

// domainRegister is the message a member signs to prove key possession at
// registration.
const domainRegister = "cloudy/consumerapi/register/v0"

// Server is the composition root for the member-facing surface: it owns the
// member directory and the layer stores, and mounts the HTTP handlers. It is
// safe for concurrent use — a single mutex guards the in-memory stores and the
// member-local narrative manifest, which is sufficient for slice 1.
type Server struct {
	platform string

	mu       sync.Mutex
	byMember map[covenant.MemberID]ed25519.PublicKey
	tree     *techtree.Tree
	catalog  *market.Catalog
	book     *covenant.Book
	locker   record.Locker
	// manifest maps a commons artifact id (hex) to the Locker hashes of its
	// member-local narrative — the front-end-local index that lets a reader
	// fetch narrative the commons deliberately does not carry.
	manifest map[string]narrativeRefs
}

type narrativeRefs struct {
	Inputs record.Hash
	Method record.Hash
	Result record.Hash
}

// directory is the covenant Directory view over the server's member map.
type directory struct{ s *Server }

func (d directory) PublicKey(m covenant.MemberID) (ed25519.PublicKey, bool) {
	pub, ok := d.s.byMember[m]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}

// noAnchors admits no assessments: slice 1 has no sealed-exchange ingress yet,
// so no assessment can be recorded and every Standing is empty-but-valid. When
// the economy/record exchange ingress lands, this is replaced by the
// record-log-backed anchors the cmd/cloudy composition root already implements.
type noAnchors struct{}

func (noAnchors) Sealed(covenant.ExchangeRef, covenant.MemberID, covenant.MemberID) bool {
	return false
}

// NewServer constructs the slice-1 composition for a platform with in-memory
// stores.
func NewServer(platform string) (*Server, error) {
	if platform == "" {
		return nil, errors.New("consumerapi: platform must be set")
	}
	tree, err := techtree.NewTree(platform)
	if err != nil {
		return nil, err
	}
	catalog, err := market.NewCatalog(platform)
	if err != nil {
		return nil, err
	}
	s := &Server{
		platform: platform,
		byMember: make(map[covenant.MemberID]ed25519.PublicKey),
		tree:     tree,
		catalog:  catalog,
		locker:   record.NewMemLocker(),
		manifest: make(map[string]narrativeRefs),
	}
	book, err := covenant.NewBook(platform, nil, directory{s}, noAnchors{}, covenant.NewMemStore())
	if err != nil {
		return nil, err
	}
	s.book = book
	return s, nil
}

// Handler returns the mounted HTTP router for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/members", s.handleRegister)
	mux.HandleFunc("GET /api/v1/members/{id}/standing", s.handleStanding)
	mux.HandleFunc("POST /api/v1/claims", s.handleAnchorClaim)
	mux.HandleFunc("GET /api/v1/claims/{id}", s.handleGetClaim)
	mux.HandleFunc("POST /api/v1/references", s.handleAddReference)
	mux.HandleFunc("GET /api/v1/market/categories", s.handleCategories)
	mux.HandleFunc("POST /api/v1/market/listings", s.handleCreateListing)
	mux.HandleFunc("GET /api/v1/market/listings", s.handleBrowseListings)
	mux.HandleFunc("GET /api/v1/market/listings/{id}", s.handleGetListing)
	return mux
}

// registered reports whether pub is a registered member key (caller holds mu).
func (s *Server) registered(pub ed25519.PublicKey) bool {
	m := covenant.MemberIDFor(s.platform, pub)
	stored, ok := s.byMember[m]
	return ok && stored.Equal(pub)
}

// registerChallenge is the canonical message a member signs to prove key
// possession at registration.
func (s *Server) registerChallenge(pub ed25519.PublicKey) []byte {
	return canon.New(domainRegister).String(s.platform).Bytes(pub).Sum()
}

// --- JSON + hex helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeHex32(s string) ([32]byte, bool) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

func decodeKey(s string) (ed25519.PublicKey, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(b), true
}

func decodeSig(s string) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, false
	}
	return b, true
}

func hx(b []byte) string { return hex.EncodeToString(b) }
