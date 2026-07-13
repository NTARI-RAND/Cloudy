package dispute

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Sentinel errors returned (wrapped, with a specific reason) by the Registry
// and the Store; branch with errors.Is.
var (
	// ErrInvalid: a malformed artifact, a platform mismatch, an unanchored or
	// non-party exchange, an incoherent remedy, or an unknown case.
	ErrInvalid = errors.New("dispute: invalid artifact")
	// ErrDuplicate: a repeated artifact leaf ID, or a second live (non-terminal)
	// case for the same (exchange, complainant, respondent).
	ErrDuplicate = errors.New("dispute: duplicate artifact or a case is already open for this exchange and pair")
	// ErrClosed: a ruling or withdrawal was submitted against a case that is
	// not open (already resolved or withdrawn).
	ErrClosed = errors.New("dispute: case is not open")
	// ErrUnauthorized: a ruling lacking threshold adjudicator signatures, or a
	// withdrawal not signed by the case's complainant.
	ErrUnauthorized = errors.New("dispute: insufficient or invalid authorization")
	// ErrAdjudicated: an Opening for an (exchange, complainant, respondent) whose
	// prior dispute was RESOLVED by a ruling. A resolved exchange is settled and
	// cannot be re-disputed — this is what prevents a second ruling, and thus a
	// second refund/escalation, over one exchange. A WITHDRAWN dispute, by
	// contrast, leaves the exchange re-openable.
	ErrAdjudicated = errors.New("dispute: exchange already adjudicated; a resolved dispute cannot be re-opened")
)

// Charter is the dispute domain's out-of-band configuration: the platform it
// is scoped to and the generic staff roster empowered to render rulings. It
// mirrors economy.Genesis and names no organization — the deciding role is
// the generic Adjudicators set, never a company name. Threshold distinct
// adjudicator signatures render a ruling.
type Charter struct {
	Platform     string              // the platform every artifact is bound to
	Adjudicators []ed25519.PublicKey // authorized staff keys
	Threshold    int                 // distinct adjudicator sigs to render a ruling; 1 <= Threshold <= len(Adjudicators)
}

// Anchors is the leaf-clean cross-layer gate (mirrors covenant.Anchors): it
// reports whether an exchange reference names a sealed record entry binding
// exactly these two members. The composition root wires it to the record
// layer; dispute sees only opaque values and public keys, preserving the
// no-cross-layer-import rule.
type Anchors interface {
	// Sealed reports whether exchange is a sealed entry between complainant
	// and respondent (in either party order).
	Sealed(exchange ExchangeRef, complainant, respondent ed25519.PublicKey) bool
}

// Admitted is an artifact the Registry has verified and admitted. It cannot be
// constructed outside this package (unexported fields, no constructor), so a
// Store can hold admitted artifacts but can never mint one — writing around
// the Registry is a compile error. Exactly one of the three artifact pointers
// is non-nil.
type Admitted struct {
	dispute    DisputeID // the case this artifact belongs to
	id         DisputeID // this artifact's own leaf ID; the Store's dedup key
	opening    *Opening
	ruling     *Ruling
	withdrawal *Withdrawal
}

// Dispute returns the case ID this artifact belongs to.
func (a Admitted) Dispute() DisputeID { return a.dispute }

// ID returns this artifact's own leaf ID (the Store's dedup key).
func (a Admitted) ID() DisputeID { return a.id }

// Opening returns the admitted opening and true if this artifact is one; the
// returned Opening is a deep copy.
func (a Admitted) Opening() (Opening, bool) {
	if a.opening == nil {
		return Opening{}, false
	}
	return a.opening.clone(), true
}

// Ruling returns the admitted ruling and true if this artifact is one; the
// returned Ruling is a deep copy.
func (a Admitted) Ruling() (Ruling, bool) {
	if a.ruling == nil {
		return Ruling{}, false
	}
	return a.ruling.clone(), true
}

// Withdrawal returns the admitted withdrawal and true if this artifact is one;
// the returned Withdrawal is a deep copy.
func (a Admitted) Withdrawal() (Withdrawal, bool) {
	if a.withdrawal == nil {
		return Withdrawal{}, false
	}
	return a.withdrawal.clone(), true
}

// opensCase reports whether a is an opening, and if so returns the case's
// (exchange, complainant, respondent) tuple key used by the Store to enforce
// one-live-case-per-tuple. Used by in-package Store implementations.
func (a Admitted) opensCase() (string, bool) {
	if a.opening == nil {
		return "", false
	}
	o := a.opening
	return string(o.Exchange[:]) + "\x00" + string(o.Complainant) + "\x00" + string(o.Respondent), true
}

// Store is the append-only persistence port; no update, no delete. It trades
// only in the package-minted Admitted. Implementations MUST reject a duplicate
// artifact ID and a second live case for the same (exchange, complainant,
// respondent) with ErrDuplicate, atomically under concurrent Appends, and MUST
// return defensive copies from ByDispute in append order.
type Store interface {
	// Append durably records a, or returns ErrDuplicate for a repeated
	// artifact ID or a second live case for the same tuple, and ErrInvalid for
	// the zero Admitted.
	Append(a Admitted) error
	// ByDispute returns every admitted artifact for a case, in append order, as
	// defensive copies; an unknown case yields an empty slice, not an error.
	ByDispute(id DisputeID) ([]Admitted, error)
}

// Registry is the only admission path into the dispute record and the only
// reader of case state; there is no operator write and no way to record an
// artifact that is not properly signed and gated. It knows its platform and
// adjudicator roster (the Charter) so it can re-verify every ruling.
type Registry struct {
	charter Charter
	anchors Anchors
	store   Store
}

// NewRegistry returns a Registry enforcing dispute rules over the given
// charter, anchor predicate, and store. It validates the charter (non-empty
// platform, at least one adjudicator with a canonical-length key, and
// 1 <= Threshold <= len(Adjudicators)) and requires non-nil dependencies. It
// stores its own copies of the adjudicator keys, so a caller mutating its
// slice afterward cannot alter admission.
func NewRegistry(c Charter, anchors Anchors, store Store) (*Registry, error) {
	if c.Platform == "" {
		return nil, errors.New("dispute: NewRegistry: empty platform")
	}
	if len(c.Adjudicators) == 0 {
		return nil, errors.New("dispute: NewRegistry: empty adjudicator roster")
	}
	if c.Threshold < 1 || c.Threshold > len(c.Adjudicators) {
		return nil, fmt.Errorf("dispute: NewRegistry: threshold %d must satisfy 1 <= threshold <= %d adjudicators",
			c.Threshold, len(c.Adjudicators))
	}
	owned := make([]ed25519.PublicKey, len(c.Adjudicators))
	for i, k := range c.Adjudicators {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("dispute: NewRegistry: adjudicator %d key is malformed", i)
		}
		owned[i] = append(ed25519.PublicKey(nil), k...)
	}
	if anchors == nil {
		return nil, errors.New("dispute: NewRegistry: nil Anchors")
	}
	if store == nil {
		return nil, errors.New("dispute: NewRegistry: nil Store")
	}
	return &Registry{
		charter: Charter{Platform: c.Platform, Adjudicators: owned, Threshold: c.Threshold},
		anchors: anchors,
		store:   store,
	}, nil
}

// Open admits a complainant-signed Opening: it verifies the opening, matches
// the platform, and gates on the Anchors predicate (the disputed exchange must
// be a sealed entry between exactly these two members), then admits it,
// putting the case in StateOpen. The Store atomically rejects a second live
// case for the same (exchange, complainant, respondent) with ErrDuplicate.
// Returns the new case's DisputeID.
func (r *Registry) Open(o Opening) (DisputeID, error) {
	if !o.Verify() {
		return DisputeID{}, fmt.Errorf("%w: opening does not verify", ErrInvalid)
	}
	if o.Platform != r.charter.Platform {
		return DisputeID{}, fmt.Errorf("%w: opening platform %q does not match charter platform %q", ErrInvalid, o.Platform, r.charter.Platform)
	}
	if !r.anchors.Sealed(o.Exchange, o.Complainant, o.Respondent) {
		return DisputeID{}, fmt.Errorf("%w: exchange is not sealed between these two members", ErrInvalid)
	}
	id := o.ID()
	oc := o.clone()
	if err := r.store.Append(Admitted{dispute: id, id: id, opening: &oc}); err != nil {
		return DisputeID{}, err
	}
	return id, nil
}

// Rule admits a staff-signed Ruling on an open case: it matches the platform,
// verifies the ruling carries at least Threshold distinct authorized
// adjudicator signatures, checks the remedy is coherent with the ruling's
// Mode, confirms the case exists and is open, and confirms the echoed exchange
// matches the case's. On success the case becomes StateResolved. The exchange
// gate was already passed at Open; Mode is supplied by the caller (the seam
// maps the ledger's policy), never inferred here.
func (r *Registry) Rule(ru Ruling) error {
	if ru.Platform != r.charter.Platform {
		return fmt.Errorf("%w: ruling platform %q does not match charter platform %q", ErrInvalid, ru.Platform, r.charter.Platform)
	}
	if !validMode(ru.Mode) {
		return fmt.Errorf("%w: unknown ruling mode", ErrInvalid)
	}
	if !validFinding(ru.Finding) {
		return fmt.Errorf("%w: unknown finding", ErrInvalid)
	}
	if err := ru.Remedy.validate(ru.Mode); err != nil {
		return err
	}
	if !ru.Verify(r.charter) {
		return fmt.Errorf("%w: ruling lacks %d distinct authorized adjudicator signatures", ErrUnauthorized, r.charter.Threshold)
	}
	c, err := r.Case(ru.Dispute)
	if err != nil {
		return err
	}
	if c.state != StateOpen {
		return fmt.Errorf("%w: cannot rule on a %s case", ErrClosed, c.state)
	}
	if ru.Exchange != c.exchange {
		return fmt.Errorf("%w: ruling exchange does not match the case", ErrInvalid)
	}
	ruc := ru.clone()
	return r.store.Append(Admitted{dispute: ru.Dispute, id: ru.ID(), ruling: &ruc})
}

// Withdraw admits a complainant-signed Withdrawal on an open case: it matches
// the platform, confirms the case exists and is open, and verifies the
// signature against the complainant resolved from the case's Opening. On
// success the case becomes StateWithdrawn.
func (r *Registry) Withdraw(w Withdrawal) error {
	if w.Platform != r.charter.Platform {
		return fmt.Errorf("%w: withdrawal platform %q does not match charter platform %q", ErrInvalid, w.Platform, r.charter.Platform)
	}
	c, err := r.Case(w.Dispute)
	if err != nil {
		return err
	}
	if c.state != StateOpen {
		return fmt.Errorf("%w: cannot withdraw a %s case", ErrClosed, c.state)
	}
	if !w.Verify(c.complainant) {
		return fmt.Errorf("%w: withdrawal is not signed by the case's complainant", ErrUnauthorized)
	}
	wc := w.clone()
	return r.store.Append(Admitted{dispute: w.Dispute, id: w.leafID(), withdrawal: &wc})
}

// Case replays the artifacts of one case from the Store and folds them into
// the read model: Opening -> StateOpen; a valid Ruling -> StateResolved; a
// Withdrawal -> StateWithdrawn. It never trusts a stored scalar — state is
// derived from the ordered artifacts. An unknown case (no artifacts) returns
// an error wrapping ErrInvalid; a case whose first artifact is not an opening
// is a Store contract violation and also errors.
func (r *Registry) Case(id DisputeID) (Case, error) {
	ads, err := r.store.ByDispute(id)
	if err != nil {
		return Case{}, err
	}
	if len(ads) == 0 {
		return Case{}, fmt.Errorf("%w: no such dispute", ErrInvalid)
	}
	var c Case
	c.id = id
	seenOpening := false
	for i, ad := range ads {
		switch {
		case ad.opening != nil:
			if i != 0 || seenOpening {
				return Case{}, fmt.Errorf("%w: store contract violation: opening is not the sole first artifact of the case", ErrInvalid)
			}
			seenOpening = true
			o := ad.opening
			c.exchange = o.Exchange
			c.complainant = append(ed25519.PublicKey(nil), o.Complainant...)
			c.respondent = append(ed25519.PublicKey(nil), o.Respondent...)
			c.state = StateOpen
		case ad.ruling != nil:
			c.state = StateResolved
			c.finding = ad.ruling.Finding
			c.remedy = ad.ruling.Remedy.clone()
		case ad.withdrawal != nil:
			c.state = StateWithdrawn
		}
	}
	if !seenOpening {
		return Case{}, fmt.Errorf("%w: store contract violation: case has no opening", ErrInvalid)
	}
	return c, nil
}
