package dispute

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Mode is dispute's local view of the platform's escrow-now/credit-later
// policy. It is a DISTINCT type from economy.Mode — dispute never imports
// economy; the composition seam maps economy.Mode to this — so the two are
// legible against each other but not the same type. The zero value is
// invalid; a Ruling's Mode is supplied by the caller (the seam reads the
// ledger's policy), never inferred by this package.
type Mode uint8

const (
	// ModeEscrow: the disputed fiat sits at the coordinator, which this
	// package structurally cannot touch. A ruling therefore carries an
	// Escalation — a staff-signed directive to the coordinator — and moves no
	// money.
	ModeEscrow Mode = iota + 1
	// ModeCredit: the exchange settled in Cloudy's own credit. A ruling
	// carries a reputational HarmDisposition and, optionally, a voluntary
	// RefundDirective; forced clawback is impossible by economy invariant.
	ModeCredit
)

func validMode(m Mode) bool { return m == ModeEscrow || m == ModeCredit }

// Finding is the adjudicated outcome of a case. The zero value is invalid.
type Finding uint8

const (
	FindingForComplainant Finding = iota + 1 // the complainant's grievance is upheld
	FindingForRespondent                     // the respondent prevails
	FindingSplit                             // fault or remedy is shared
	FindingNoFault                           // no fault found on either side
)

func validFinding(f Finding) bool {
	switch f {
	case FindingForComplainant, FindingForRespondent, FindingSplit, FindingNoFault:
		return true
	}
	return false
}

// HarmDisposition is the credit-mode reputational outcome: whether the harm
// flag raised by the disputed exchange stands or is expunged. The zero value
// is invalid.
//
// NOTE: covenant is immutable — there is NO retraction API and an admitted
// No Trust (-1) is permanent (covenant.Standing.Harm keeps counting it).
// HarmExpunged therefore CANNOT delete a covenant assessment; it is an
// adjudicated overlay recorded in the dispute/record trail. A reputation
// presentation must compose both the covenant standing and the dispute
// rulings; reading covenant.Standing alone will still see the harm.
type HarmDisposition uint8

const (
	HarmUpheld   HarmDisposition = iota + 1 // the harm assessment stands
	HarmExpunged                            // the harm is adjudicated away as an overlay (not a covenant deletion)
)

func validHarm(h HarmDisposition) bool { return h == HarmUpheld || h == HarmExpunged }

// CoordinatorAction is the escrow-mode escalation directive the coordinator
// interprets. The zero value is invalid.
type CoordinatorAction uint8

const (
	ActionRefundComplainant CoordinatorAction = iota + 1 // direct escrowed fiat back to the complainant
	ActionReleaseRespondent                              // release escrowed fiat to the respondent
	ActionSplit                                          // split the escrowed fiat
)

func validCoordinatorAction(a CoordinatorAction) bool {
	switch a {
	case ActionRefundComplainant, ActionReleaseRespondent, ActionSplit:
		return true
	}
	return false
}

// Escalation is an escrow-mode financial remedy: a staff-signed directive to
// the coordinator. Units is an OPAQUE quantity the coordinator maps to
// escrowed fiat — deliberately a bare uint64, never an economy.Amount and
// never a fiat type — so no fiat reference leaks into the JFA layers.
type Escalation struct {
	Action CoordinatorAction
	Units  uint64
}

// RefundDirective is a credit-mode VOLUNTARY refund recommendation. Units is
// magnitude only; the direction (original payee -> original payer) is implied
// by the Finding and resolved at the seam, which constructs an UNSIGNED
// economy.Spend template the payee signs voluntarily. dispute can never sign
// or force it.
type RefundDirective struct {
	Units uint64
}

// Remedy is the mode-appropriate remedy carried by a Ruling. Exactly one shape
// is coherent per Mode; validate enforces it.
type Remedy struct {
	Escalation *Escalation      // set iff ModeEscrow
	Harm       HarmDisposition  // set iff ModeCredit
	Refund     *RefundDirective // optional, ModeCredit only
}

// validate enforces mode/remedy coherence: ModeEscrow requires a valid
// Escalation and zero credit-mode fields; ModeCredit requires a valid Harm and
// no Escalation (Refund optional). Returns an error wrapping ErrInvalid.
func (r Remedy) validate(m Mode) error {
	switch m {
	case ModeEscrow:
		if r.Escalation == nil {
			return fmt.Errorf("%w: an escrow ruling requires an Escalation", ErrInvalid)
		}
		if !validCoordinatorAction(r.Escalation.Action) {
			return fmt.Errorf("%w: escalation names an unknown coordinator action", ErrInvalid)
		}
		if r.Harm != 0 || r.Refund != nil {
			return fmt.Errorf("%w: an escrow ruling must not carry credit-mode remedy fields", ErrInvalid)
		}
		return nil
	case ModeCredit:
		if r.Escalation != nil {
			return fmt.Errorf("%w: a credit ruling must not carry an escrow Escalation", ErrInvalid)
		}
		if !validHarm(r.Harm) {
			return fmt.Errorf("%w: a credit ruling requires a valid HarmDisposition", ErrInvalid)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown ruling mode", ErrInvalid)
	}
}

// clone returns a deep copy of the remedy whose pointer members share no
// memory with r.
func (r Remedy) clone() Remedy {
	out := Remedy{Harm: r.Harm}
	if r.Escalation != nil {
		e := *r.Escalation
		out.Escalation = &e
	}
	if r.Refund != nil {
		f := *r.Refund
		out.Refund = &f
	}
	return out
}

// Ruling is a staff-authored, mode-aware decision on a case. Its signatures
// are a threshold of distinct authorized adjudicator signatures verified
// against a Charter (mirrors economy.PolicyChange). The only member-authored
// narrative is the rationale text, which lives member-local; the commons
// carries only RationaleHash.
type Ruling struct {
	Platform      string      // must match the registry's platform; inside CanonicalBytes
	Dispute       DisputeID   // the case this rules; == Opening.ID()
	Exchange      ExchangeRef // echoed for standalone verification
	Mode          Mode        // supplied by the caller (the seam), never inferred here
	Finding       Finding
	Remedy        Remedy
	RationaleHash [32]byte  // SHA-256 of the member-local rationale text; the text never enters the commons
	RuledAt       time.Time // set via the constructors below
	Sigs          [][]byte  // threshold adjudicator sigs over CanonicalBytes; excluded from CanonicalBytes
}

// NewEscrowRuling builds a well-formed ModeEscrow ruling carrying an
// Escalation directive — the ergonomic, hard-to-misuse constructor.
func NewEscrowRuling(platform string, dispute DisputeID, exchange ExchangeRef, finding Finding, action CoordinatorAction, units uint64, rationaleHash [32]byte, at time.Time) Ruling {
	return Ruling{
		Platform:      platform,
		Dispute:       dispute,
		Exchange:      exchange,
		Mode:          ModeEscrow,
		Finding:       finding,
		Remedy:        Remedy{Escalation: &Escalation{Action: action, Units: units}},
		RationaleHash: rationaleHash,
		RuledAt:       at,
	}
}

// NewCreditRuling builds a well-formed ModeCredit ruling carrying a
// HarmDisposition and an optional voluntary RefundDirective. A non-nil refund
// is copied, so the caller's value cannot alter the ruling afterward.
func NewCreditRuling(platform string, dispute DisputeID, exchange ExchangeRef, finding Finding, harm HarmDisposition, refund *RefundDirective, rationaleHash [32]byte, at time.Time) Ruling {
	var rd *RefundDirective
	if refund != nil {
		cp := *refund
		rd = &cp
	}
	return Ruling{
		Platform:      platform,
		Dispute:       dispute,
		Exchange:      exchange,
		Mode:          ModeCredit,
		Finding:       finding,
		Remedy:        Remedy{Harm: harm, Refund: rd},
		RationaleHash: rationaleHash,
		RuledAt:       at,
	}
}

// CanonicalBytes returns the deterministic signing payload (canon encoder,
// domain tag "cloudy/dispute/ruling/v0") with Sigs excluded. The remedy is
// encoded TOTALLY and unambiguously — escalation presence and fields, then the
// harm byte, then refund presence and units — so the bytes are well-defined
// regardless of Mode; coherence with Mode is enforced separately by
// Remedy.validate. Field order: platform, dispute, exchange, mode, finding,
// escalation(present,action,units), harm, refund(present,units), rationaleHash,
// ruledAt.
func (r Ruling) CanonicalBytes() []byte {
	b := canon.New(domainRuling)
	b.String(r.Platform)
	b.Bytes(r.Dispute[:])
	b.Bytes(r.Exchange[:])
	b.Uint64(uint64(r.Mode))
	b.Uint64(uint64(r.Finding))
	if r.Remedy.Escalation != nil {
		b.Bool(true)
		b.Uint64(uint64(r.Remedy.Escalation.Action))
		b.Uint64(r.Remedy.Escalation.Units)
	} else {
		b.Bool(false)
	}
	b.Uint64(uint64(r.Remedy.Harm))
	if r.Remedy.Refund != nil {
		b.Bool(true)
		b.Uint64(r.Remedy.Refund.Units)
	} else {
		b.Bool(false)
	}
	b.Bytes(r.RationaleHash[:])
	b.Time(r.RuledAt)
	return b.Sum()
}

// Sign appends one adjudicator signature over CanonicalBytes (four-eyes
// friendly: call once per panel member).
func (r *Ruling) Sign(priv ed25519.PrivateKey) {
	r.Sigs = append(r.Sigs, ed25519.Sign(priv, r.CanonicalBytes()))
}

// Verify reports whether at least c.Threshold DISTINCT authorized adjudicator
// keys from c have valid signatures in Sigs; non-roster and duplicate
// signatures count nothing, and wrong-length signatures are rejected before
// ed25519 verification (mirrors economy.PolicyChange.Verify).
func (r Ruling) Verify(c Charter) bool {
	if c.Threshold < 1 {
		return false
	}
	payload := r.CanonicalBytes()
	seen := make(map[string]bool, len(c.Adjudicators))
	distinct := 0
	for _, sig := range r.Sigs {
		if len(sig) != ed25519.SignatureSize {
			continue
		}
		for _, pub := range c.Adjudicators {
			if len(pub) != ed25519.PublicKeySize || seen[string(pub)] {
				continue
			}
			if ed25519.Verify(pub, payload, sig) {
				seen[string(pub)] = true
				distinct++
				break
			}
		}
	}
	return distinct >= c.Threshold
}

// ID returns the ruling artifact's leaf hash over its canonical bytes plus its
// ordered signatures, under the leaf domain tag — the Store's dedup key for
// this artifact.
func (r Ruling) ID() DisputeID {
	b := canon.New(domainID)
	b.Bytes(r.CanonicalBytes())
	b.Count(len(r.Sigs))
	for _, s := range r.Sigs {
		b.Bytes(s)
	}
	return DisputeID(sha256.Sum256(b.Sum()))
}

// clone returns a deep copy whose signature slices and remedy pointers share
// no memory with r.
func (r Ruling) clone() Ruling {
	out := r
	out.Remedy = r.Remedy.clone()
	if r.Sigs != nil {
		out.Sigs = make([][]byte, len(r.Sigs))
		for i, s := range r.Sigs {
			out.Sigs[i] = append([]byte(nil), s...)
		}
	}
	return out
}
