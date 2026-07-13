// Package consumerapi is Cloudy's member-facing JSON API — the surface the
// React Native app talks to, and the first member-facing ingress the headless
// composition root (cmd/cloudy) said did not yet exist. Slice 1 delivered
// onboarding, the Technology Tree (techtree), and the hardware Market; slice 2
// adds the four-leaf member economy: Drops (the dialog-sealed record, with the
// operator's signed checkpoint honestly labeled a single-witness stand-in),
// LBTAS assessments anchored to sealed dialogs, payer-signed credit spends
// (refused with a plain 409 while the governed policy is escrow mode), and
// dispute filing/withdrawal (no adjudicator key exists in-process, so no
// ruling is producible here). Settlement, contribution control, and storage
// are later slices; lifecycle witnessing of disputes is Phase-3 federation
// work and is named, not simulated.
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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/dispute"
	"github.com/NTARI-RAND/Cloudy/internal/economy"
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

	// The operator's ephemeral record-log keypair. The operator legitimately
	// holds its own checkpoint-signing key — what it can never hold is a key
	// that produces a member seal, a steward PolicyChange, or an adjudicator
	// ruling; those private keys are discarded at construction, so none of
	// those artifacts are signable in this process.
	operatorPub  ed25519.PublicKey
	operatorPriv ed25519.PrivateKey

	mu        sync.Mutex
	byMember  map[covenant.MemberID]ed25519.PublicKey
	byAccount map[economy.AccountID]ed25519.PublicKey
	tree      *techtree.Tree
	catalog   *market.Catalog
	book      *covenant.Book
	locker    record.Locker

	// The four-leaf member economy, composed here exactly as cmd/cloudy
	// composes it: one shared member directory, one operator Drops log, one
	// Entry.ID()->seq index serving both cross-layer anchor joins.
	recStore record.Store
	opLog    *record.Log
	logID    record.Hash
	index    map[record.Hash]uint64
	ledger   *economy.Ledger
	ecoStore *economy.MemStore
	registry *dispute.Registry

	// The claim-lifecycle log (Part IV): every dispute transition commits
	// here as it happens, checkpointed and witnessable exactly like the
	// dialog log. The filing intake is the ONE witness write; in this
	// process it is operator-run, so every receipt it issues is honestly
	// labeled non-independent — the stand-in until the witness relay and
	// real independent intake witnesses exist (Phase 3).
	lifeLog   *record.LifecycleLog
	lifeStore *record.MemTransitionStore
	lifeID    record.Hash
	intake    *record.FilingIntake

	// operatorMember is the operator's own MemberID: the operator registers
	// in its own directory at construction (single participant identity —
	// the adjudicating operator is a member like any other, answerable
	// through the same covenant). disputesByExchange indexes claims by the
	// exchange they dispute, for the adjudication-relation anchor.
	operatorMember     covenant.MemberID
	disputesByExchange map[record.Hash][]dispute.DisputeID

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

// directory is the covenant Directory view over the server's member map, and
// accountDirectory the economy view over the account map — two typed views of
// the ONE shared registry (Go method sets cannot overload PublicKey by ID
// type). Every view returns a COPY of the registered key, so no caller can
// corrupt the registry through a returned slice.
type directory struct{ s *Server }

func (d directory) PublicKey(m covenant.MemberID) (ed25519.PublicKey, bool) {
	pub, ok := d.s.byMember[m]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}

type accountDirectory struct{ s *Server }

func (d accountDirectory) PublicKey(a economy.AccountID) (ed25519.PublicKey, bool) {
	pub, ok := d.s.byAccount[a]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}

// recAnchors implements covenant.Anchors against the operator's Drops log:
// resolve both MemberIDs through the shared directory, find the entry whose
// ID() equals the ExchangeRef via the server's ID->seq index, and demand an
// entry bound to THIS operator log that fully verifies and is sealed by
// exactly the resolved pair, in either order. Same join as cmd/cloudy's.
// Callers hold s.mu (the Book calls Sealed inside Record, which handlers
// already serialize), so the anchor reads take no lock of their own.
type recAnchors struct{ s *Server }

func (a recAnchors) Sealed(exchange covenant.ExchangeRef, assessor, subject covenant.MemberID) bool {
	assessorKey, ok := a.s.byMember[assessor]
	if !ok {
		return false
	}
	subjectKey, ok := a.s.byMember[subject]
	if !ok {
		return false
	}
	id := record.Hash(exchange)
	seq, ok := a.s.index[id]
	if !ok {
		return false
	}
	e, err := a.s.recStore.At(seq)
	if err != nil || e.ID() != id || e.Log != a.s.logID || !e.Verify() {
		return false
	}
	return (bytes.Equal(e.Proposer, assessorKey) && bytes.Equal(e.Acceptor, subjectKey)) ||
		(bytes.Equal(e.Proposer, subjectKey) && bytes.Equal(e.Acceptor, assessorKey))
}

// Adjudicated implements the adjudication-relation anchor: the assessor was
// a genuine party (complainant or respondent) to a claim on this exchange,
// and the subject is the adjudicating operator's own MemberID. Callers hold
// s.mu. Sybil posture: adjudication-conduct and verdict-satisfaction
// standing can only accumulate from members with real, anchored claims —
// there is nothing here for a bot swarm to inflate.
func (a recAnchors) Adjudicated(exchange covenant.ExchangeRef, assessor, subject covenant.MemberID) bool {
	if subject != a.s.operatorMember {
		return false
	}
	assessorKey, ok := a.s.byMember[assessor]
	if !ok {
		return false
	}
	ids := a.s.disputesByExchange[record.Hash(exchange)]
	for _, id := range ids {
		c, err := a.s.registry.Case(id)
		if err != nil {
			continue
		}
		if bytes.Equal(c.Complainant(), assessorKey) || bytes.Equal(c.Respondent(), assessorKey) {
			return true
		}
	}
	return false
}

// dispAnchors is the dispute-side twin: the same join on the same index, but
// the dispute port speaks raw ed25519 keys, so the party match compares keys
// directly. The [32]byte conversion between record.Hash and the two layers'
// ExchangeRef types happens in these two views and nowhere else.
type dispAnchors struct{ s *Server }

func (a dispAnchors) Sealed(exchange dispute.ExchangeRef, complainant, respondent ed25519.PublicKey) bool {
	id := record.Hash(exchange)
	seq, ok := a.s.index[id]
	if !ok {
		return false
	}
	e, err := a.s.recStore.At(seq)
	if err != nil || e.ID() != id || e.Log != a.s.logID || !e.Verify() {
		return false
	}
	return (bytes.Equal(e.Proposer, complainant) && bytes.Equal(e.Acceptor, respondent)) ||
		(bytes.Equal(e.Proposer, respondent) && bytes.Equal(e.Acceptor, complainant))
}

// appendEntry is the ONLY append path into the operator log: it appends and
// records the entry's ID->seq mapping, so every assessment or dispute of that
// exchange can anchor to it. Appending via s.opLog directly would strand the
// entry unanchorable forever. Caller holds s.mu.
func (s *Server) appendEntry(e record.Entry) (uint64, error) {
	seq, err := s.opLog.Append(e)
	if err != nil {
		return 0, err
	}
	s.index[e.ID()] = seq
	return seq, nil
}

// NewServer constructs the member-facing composition for a platform with
// in-memory stores and ephemeral keys, exactly as honest about what it is as
// cmd/cloudy: nothing here is a durable deployment. The steward and
// adjudicator PRIVATE keys are discarded at construction — no PolicyChange
// (so no escrow->credit transition) and no ruling is signable in this
// process. Only the operator's checkpoint-signing key is held, because
// serving signed checkpoints is the operator's own job.
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
	operatorPub, operatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	stewardPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	adjudicatorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &Server{
		platform:     platform,
		operatorPub:  operatorPub,
		operatorPriv: operatorPriv,
		byMember:     make(map[covenant.MemberID]ed25519.PublicKey),
		byAccount:    make(map[economy.AccountID]ed25519.PublicKey),
		tree:         tree,
		catalog:      catalog,
		locker:       record.NewMemLocker(),
		index:        make(map[record.Hash]uint64),
		manifest:     make(map[string]narrativeRefs),
	}
	s.recStore = record.NewMemStore()
	s.opLog, err = record.OpenLog(operatorPub, s.recStore)
	if err != nil {
		return nil, err
	}
	s.logID = record.LogID(operatorPub)
	s.ecoStore = economy.NewMemStore()
	s.ledger, err = economy.Open(economy.Genesis{
		Platform:  platform,
		Stewards:  []ed25519.PublicKey{stewardPub},
		Threshold: 1,
		Policy:    economy.Policy{Mode: economy.ModeEscrow},
	}, accountDirectory{s}, s.ecoStore)
	if err != nil {
		return nil, err
	}
	s.book, err = covenant.NewBook(platform, nil, directory{s}, recAnchors{s}, covenant.NewMemStore())
	if err != nil {
		return nil, err
	}
	s.registry, err = dispute.NewRegistry(dispute.Charter{
		Platform:     platform,
		Adjudicators: []ed25519.PublicKey{adjudicatorPub},
		Threshold:    1,
	}, dispAnchors{s}, dispute.NewMemStore())
	if err != nil {
		return nil, err
	}
	s.lifeStore = record.NewMemTransitionStore()
	s.lifeLog, err = record.OpenLifecycleLog(operatorPub, s.lifeStore)
	if err != nil {
		return nil, err
	}
	s.lifeID = record.LifecycleLogID(operatorPub)
	s.intake = record.NewFilingIntake(operatorPriv)
	// The operator registers as a member of its own platform: one identity,
	// contributor and consumer and (here) adjudicator at once — and thereby
	// RATEABLE: adjudication-conduct and verdict-satisfaction assessments
	// name this MemberID as their subject, and it can answer them.
	s.operatorMember = covenant.MemberIDFor(platform, operatorPub)
	owned := append(ed25519.PublicKey(nil), operatorPub...)
	s.byMember[s.operatorMember] = owned
	s.byAccount[economy.AccountIDFor(platform, operatorPub)] = owned
	s.disputesByExchange = make(map[record.Hash][]dispute.DisputeID)
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
	mux.HandleFunc("GET /api/v1/drops/log", s.handleDropsLog)
	mux.HandleFunc("GET /api/v1/drops/checkpoints", s.handleDropsCheckpoints)
	mux.HandleFunc("POST /api/v1/drops", s.handleAppendDrop)
	mux.HandleFunc("GET /api/v1/drops/{id}", s.handleGetDrop)
	mux.HandleFunc("GET /api/v1/credit/policy", s.handleCreditPolicy)
	mux.HandleFunc("GET /api/v1/credit/accounts/{id}/balance", s.handleBalance)
	mux.HandleFunc("GET /api/v1/credit/accounts/{id}/history", s.handleHistory)
	mux.HandleFunc("POST /api/v1/credit/spends", s.handlePostSpend)
	mux.HandleFunc("POST /api/v1/assessments", s.handleRecordAssessment)
	mux.HandleFunc("POST /api/v1/assessments/{id}/answers", s.handleAnswerAssessment)
	mux.HandleFunc("GET /api/v1/assessments/{id}/answer", s.handleGetAnswer)
	mux.HandleFunc("POST /api/v1/disputes", s.handleOpenDispute)
	mux.HandleFunc("GET /api/v1/disputes/{id}", s.handleGetDispute)
	mux.HandleFunc("POST /api/v1/disputes/{id}/withdraw", s.handleWithdrawDispute)
	mux.HandleFunc("GET /api/v1/lifecycle/checkpoints", s.handleLifecycleCheckpoints)
	mux.HandleFunc("GET /api/v1/drops/checkpoints/consistency", s.handleDropsConsistency)
	mux.HandleFunc("GET /api/v1/lifecycle/checkpoints/consistency", s.handleLifecycleConsistency)
	mux.HandleFunc("GET /api/v1/lifecycle/claims/{id}", s.handleLifecycleClaim)
	mux.HandleFunc("GET /api/v1/drops/{id}/proof", s.handleDropProof)
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
