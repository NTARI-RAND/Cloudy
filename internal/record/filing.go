package record

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Filing intake — the deliberate, bounded exception to the witness-as-
// observer role (architecture, Record invariants): a harm claim's filing
// commitment is made AT AN INDEPENDENT WITNESS, upstream of the operator
// that will adjudicate it, so the operator is absent from its own claim's
// birth — it cannot add filing friction, shape a claim, or shed it before
// the claim exists in the record. The witness accepts exactly ONE write —
// claim-creation — and nothing else; it MUST NOT become a second log for any
// other event.
//
// PII discipline binds hardest here: a commitment is a claim id, an exchange
// reference, a TYPE hash, an instant, and the filer's key — the structural
// fact that a claim of a kind exists. The narrative and the identities stay
// front-end-local and erasable.
const (
	domainFiling        = "drops/lifecycle-filing/v1"
	domainFilingReceipt = "drops/lifecycle-filing-receipt/v1"
)

// FilingCommitment is the filer-signed structural fact lodged at a witness
// before the operator acts.
type FilingCommitment struct {
	Claim     Hash              // the claim id the dispute layer will use (opaque here)
	Exchange  Hash              // leaf ID of the disputed sealed dialog
	TypeHash  Hash              // digest of the dispute-type label; a hash, never text
	At        time.Time         // UTC instant of filing
	Filer     ed25519.PublicKey // who files; signs the commitment
	Signature []byte            // ed25519 by Filer; excluded from CanonicalBytes
}

// CanonicalBytes returns the deterministic signing payload.
func (f FilingCommitment) CanonicalBytes() []byte {
	b := canon.New(domainFiling)
	b.Bytes(f.Claim[:])
	b.Bytes(f.Exchange[:])
	b.Bytes(f.TypeHash[:])
	b.Time(f.At)
	b.Bytes(f.Filer)
	return b.Sum()
}

// Sign seals the commitment with the filer's key.
func (f *FilingCommitment) Sign(priv ed25519.PrivateKey) {
	f.Signature = ed25519.Sign(priv, f.CanonicalBytes())
}

// Verify reports whether the commitment is well-formed and filer-signed.
func (f FilingCommitment) Verify() bool {
	return len(f.Filer) == ed25519.PublicKeySize &&
		len(f.Signature) == ed25519.SignatureSize &&
		f.Claim != zeroHash &&
		f.Exchange != zeroHash &&
		ed25519.Verify(f.Filer, f.CanonicalBytes(), f.Signature)
}

// FilingReceipt is the witness's countersigned acknowledgment that the
// commitment existed at ReceivedAt — the evidence an operator cannot erase a
// filing it never saw or backdate one it sat on. A receipt confers no
// authority: it proves intake, not merit.
type FilingReceipt struct {
	Commitment FilingCommitment
	Witness    ed25519.PublicKey // the intake witness
	ReceivedAt time.Time         // UTC instant of intake at the witness
	Signature  []byte            // ed25519 by Witness over the receipt payload
}

// CanonicalBytes returns the witness's signing payload: the commitment's
// canonical bytes wrapped with the intake instant under the receipt domain.
func (r FilingReceipt) CanonicalBytes() []byte {
	b := canon.New(domainFilingReceipt)
	b.Bytes(r.Commitment.CanonicalBytes())
	b.Bytes(r.Witness)
	b.Time(r.ReceivedAt)
	return b.Sum()
}

// Verify reports whether the receipt is a valid witness acknowledgment of a
// valid commitment, and that the witness is not the filer (an intake witness
// acknowledging its own filing proves nothing).
func (r FilingReceipt) Verify() bool {
	if !r.Commitment.Verify() {
		return false
	}
	if len(r.Witness) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize {
		return false
	}
	if string(r.Witness) == string(r.Commitment.Filer) {
		return false
	}
	return ed25519.Verify(r.Witness, r.CanonicalBytes(), r.Signature)
}

// IndependentOf reports whether the receipt's witness is independent of the
// given operator key — the label a surface must carry when it is not: an
// operator-run intake is a stand-in, exactly like a single-witness
// checkpoint, and must present itself as one.
func (r FilingReceipt) IndependentOf(operator ed25519.PublicKey) bool {
	return len(operator) == ed25519.PublicKeySize && string(r.Witness) != string(operator)
}

// FilingIntake is the witness-side acceptor of the ONE write. It is
// stateless beyond its key: durability of accepted receipts is the relay's
// concern (cache-and-serve), and the intake never reads, orders, or judges —
// it acknowledges existence at an instant.
type FilingIntake struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewFilingIntake returns an intake acceptor for the witness key.
func NewFilingIntake(priv ed25519.PrivateKey) *FilingIntake {
	fi := &FilingIntake{priv: priv}
	if len(priv) == ed25519.PrivateKeySize {
		fi.pub = priv.Public().(ed25519.PublicKey)
	}
	return fi
}

// Key returns the intake witness's public key.
func (fi *FilingIntake) Key() ed25519.PublicKey { return fi.pub }

// Accept validates the commitment and returns the signed receipt. It is the
// witness's only verb here — there is no read-back, no veto beyond
// malformedness, and no second write.
func (fi *FilingIntake) Accept(f FilingCommitment, at time.Time) (FilingReceipt, error) {
	if len(fi.priv) != ed25519.PrivateKeySize {
		return FilingReceipt{}, errors.New("record: intake key is malformed")
	}
	if !f.Verify() {
		return FilingReceipt{}, errors.New("record: filing commitment does not verify")
	}
	if string(f.Filer) == string(fi.pub) {
		return FilingReceipt{}, errors.New("record: an intake witness never accepts its own filing")
	}
	r := FilingReceipt{Commitment: f, Witness: fi.pub, ReceivedAt: at}
	r.Signature = ed25519.Sign(fi.priv, r.CanonicalBytes())
	return r, nil
}
