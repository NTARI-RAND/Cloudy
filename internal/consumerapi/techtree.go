package consumerapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

// claimDTO is the wire form of a techtree.Claim: every signed field, hex-coded,
// with the timestamp as unix nanoseconds so it round-trips to the exact
// time.Time the client signed (canon.Time uses UTC UnixNano, which is
// location-independent). The three narrative texts travel ALONGSIDE the signed
// claim; the server checks each hashes to the signed hash, then stores the
// text member-local in the Locker and keeps only the hash in the commons.
type claimDTO struct {
	Platform     string `json:"platform"`
	Claimant     string `json:"claimant"`    // hex ed25519 public key
	Kind         string `json:"kind"`        // fact | technique | product_spec
	InputsHash   string `json:"inputs_hash"` // hex; must equal HashNarrative(inputs)
	MethodHash   string `json:"method_hash"` // hex; must equal HashNarrative(method)
	ResultHash   string `json:"result_hash"` // hex; must equal HashNarrative(result)
	Nonce        string `json:"nonce"`       // hex 32
	AssertedAtNs int64  `json:"asserted_at_ns"`
	Signature    string `json:"signature"` // hex ed25519

	// Member-local narrative — never enters the commons; routed to the Locker.
	Inputs string `json:"inputs"`
	Method string `json:"method"`
	Result string `json:"result"`
}

func (dto claimDTO) toClaim() (techtree.Claim, bool) {
	claimant, ok := decodeKey(dto.Claimant)
	if !ok {
		return techtree.Claim{}, false
	}
	inputsHash, ok := decodeHex32(dto.InputsHash)
	if !ok {
		return techtree.Claim{}, false
	}
	methodHash, ok := decodeHex32(dto.MethodHash)
	if !ok {
		return techtree.Claim{}, false
	}
	resultHash, ok := decodeHex32(dto.ResultHash)
	if !ok {
		return techtree.Claim{}, false
	}
	nonce, ok := decodeHex32(dto.Nonce)
	if !ok {
		return techtree.Claim{}, false
	}
	sig, ok := decodeSig(dto.Signature)
	if !ok {
		return techtree.Claim{}, false
	}
	return techtree.Claim{
		Platform:   dto.Platform,
		Claimant:   claimant,
		Kind:       techtree.ClaimKind(dto.Kind),
		InputsHash: inputsHash,
		MethodHash: methodHash,
		ResultHash: resultHash,
		Nonce:      nonce,
		AssertedAt: time.Unix(0, dto.AssertedAtNs).UTC(),
		Signature:  sig,
	}, true
}

// handleAnchorClaim ingests a client-signed claim plus its narrative. It
// verifies the narrative matches the signed hashes (so the commons hash and the
// Locker content correspond), that the claim is signed by a REGISTERED member,
// and that the claim itself verifies; then it appends to the tree and stores
// the narrative member-local.
func (s *Server) handleAnchorClaim(w http.ResponseWriter, r *http.Request) {
	var dto claimDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	c, ok := dto.toClaim()
	if !ok {
		writeErr(w, http.StatusBadRequest, "malformed claim fields")
		return
	}
	// The narrative the client sends must hash to the hashes it signed.
	if techtree.HashNarrative([]byte(dto.Inputs)) != c.InputsHash ||
		techtree.HashNarrative([]byte(dto.Method)) != c.MethodHash ||
		techtree.HashNarrative([]byte(dto.Result)) != c.ResultHash {
		writeErr(w, http.StatusBadRequest, "narrative does not match the signed hashes")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registered(c.Claimant) {
		writeErr(w, http.StatusUnauthorized, "claimant is not a registered member")
		return
	}
	id, err := s.tree.AddClaim(c)
	if err != nil {
		writeErr(w, addClaimStatus(err), err.Error())
		return
	}
	// Store the narrative member-local (erasable Locker) and index it.
	s.manifest[hex.EncodeToString(id[:])] = narrativeRefs{
		Inputs: s.locker.Put([]byte(dto.Inputs)),
		Method: s.locker.Put([]byte(dto.Method)),
		Result: s.locker.Put([]byte(dto.Result)),
	}
	writeJSON(w, http.StatusCreated, map[string]string{"claim_id": hex.EncodeToString(id[:])})
}

func addClaimStatus(err error) int {
	switch {
	case errors.Is(err, techtree.ErrDuplicate):
		return http.StatusConflict
	case errors.Is(err, techtree.ErrWrongPlatform), errors.Is(err, techtree.ErrBadSignature):
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

type claimView struct {
	ClaimID    string         `json:"claim_id"`
	Platform   string         `json:"platform"`
	Claimant   string         `json:"claimant"`
	Kind       string         `json:"kind"`
	AssertedAt string         `json:"asserted_at"`
	Weight     weightDTO      `json:"citation_weight"`
	Narrative  *narrativeView `json:"narrative,omitempty"`
}

type narrativeView struct {
	Inputs string `json:"inputs"`
	Method string `json:"method"`
	Result string `json:"result"`
}

type weightDTO struct {
	Cites      int `json:"cites"`
	BuildsOn   int `json:"builds_on"`
	Reproduces int `json:"reproduces"`
	Refutes    int `json:"refutes"`
	Contests   int `json:"contests"`
}

// handleGetClaim serves a claim's structural facts, its legible citation-weight
// breakdown (never a score), and — if the narrative is held locally — the
// inputs/method/result text from the Locker. Public read.
func (s *Server) handleGetClaim(w http.ResponseWriter, r *http.Request) {
	idHex := r.PathValue("id")
	idBytes, err := hex.DecodeString(idHex)
	if err != nil || len(idBytes) != 32 {
		writeErr(w, http.StatusBadRequest, "claim id must be 32-byte hex")
		return
	}
	var id techtree.ClaimID
	copy(id[:], idBytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.tree.Claim(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "claim not found")
		return
	}
	w0 := s.tree.CitationWeight(id)
	view := claimView{
		ClaimID:    idHex,
		Platform:   c.Platform,
		Claimant:   hx(c.Claimant),
		Kind:       string(c.Kind),
		AssertedAt: c.AssertedAt.UTC().Format(time.RFC3339Nano),
		Weight: weightDTO{
			Cites: w0.Cites, BuildsOn: w0.BuildsOn, Reproduces: w0.Reproduces,
			Refutes: w0.Refutes, Contests: w0.Contests,
		},
	}
	if refs, ok := s.manifest[idHex]; ok {
		in, iok := s.locker.Get(refs.Inputs)
		me, mok := s.locker.Get(refs.Method)
		re, rok := s.locker.Get(refs.Result)
		if iok && mok && rok {
			view.Narrative = &narrativeView{Inputs: string(in), Method: string(me), Result: string(re)}
		}
	}
	writeJSON(w, http.StatusOK, view)
}

type referenceDTO struct {
	Platform     string `json:"platform"`
	Asserter     string `json:"asserter"` // hex ed25519 public key
	Kind         string `json:"kind"`     // builds_on | cites | contests | reproduces | refutes
	From         string `json:"from"`     // hex claim id
	To           string `json:"to"`       // hex claim id
	Nonce        string `json:"nonce"`    // hex 32
	AssertedAtNs int64  `json:"asserted_at_ns"`
	Signature    string `json:"signature"` // hex ed25519
}

func (dto referenceDTO) toReference() (techtree.Reference, bool) {
	asserter, ok := decodeKey(dto.Asserter)
	if !ok {
		return techtree.Reference{}, false
	}
	from, ok := decodeHex32(dto.From)
	if !ok {
		return techtree.Reference{}, false
	}
	to, ok := decodeHex32(dto.To)
	if !ok {
		return techtree.Reference{}, false
	}
	nonce, ok := decodeHex32(dto.Nonce)
	if !ok {
		return techtree.Reference{}, false
	}
	sig, ok := decodeSig(dto.Signature)
	if !ok {
		return techtree.Reference{}, false
	}
	return techtree.Reference{
		Platform:   dto.Platform,
		Asserter:   asserter,
		Kind:       techtree.RefKind(dto.Kind),
		From:       techtree.ClaimID(from),
		To:         techtree.ClaimID(to),
		Nonce:      nonce,
		AssertedAt: time.Unix(0, dto.AssertedAtNs).UTC(),
		Signature:  sig,
	}, true
}

// handleAddReference ingests a client-signed edge (cite/contest/reproduce/etc.)
// between two claims. The tree enforces that From and To exist and that the
// asserter owns From; a contest is a new edge, never an erasure.
func (s *Server) handleAddReference(w http.ResponseWriter, r *http.Request) {
	var dto referenceDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ref, ok := dto.toReference()
	if !ok {
		writeErr(w, http.StatusBadRequest, "malformed reference fields")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registered(ref.Asserter) {
		writeErr(w, http.StatusUnauthorized, "asserter is not a registered member")
		return
	}
	id, err := s.tree.AddReference(ref)
	if err != nil {
		writeErr(w, referenceStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"reference_id": hex.EncodeToString(id[:])})
}

func referenceStatus(err error) int {
	switch {
	case errors.Is(err, techtree.ErrDuplicate):
		return http.StatusConflict
	case errors.Is(err, techtree.ErrUnknownClaim), errors.Is(err, techtree.ErrNotAsserter),
		errors.Is(err, techtree.ErrBuildsOnCycle):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}
