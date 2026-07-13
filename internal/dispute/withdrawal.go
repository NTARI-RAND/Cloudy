package dispute

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Withdrawal is the complainant's signed retraction of an open case. Only the
// complainant may withdraw, and only while the case is open; the complainant's
// key is resolved from the stored Opening at the Registry, never carried here.
type Withdrawal struct {
	Platform    string    // must match the registry's platform; inside CanonicalBytes
	Dispute     DisputeID // the case being withdrawn; == Opening.ID()
	WithdrawnAt time.Time // UTC; canon drops location and monotonic components
	Signature   []byte    // ed25519 by the complainant; excluded from CanonicalBytes
}

// CanonicalBytes returns the deterministic signing payload (canon encoder,
// domain tag "cloudy/dispute/withdrawal/v0") with Signature excluded. Field
// order: platform, dispute, withdrawnAt.
func (w Withdrawal) CanonicalBytes() []byte {
	b := canon.New(domainWithdrawal)
	b.String(w.Platform)
	b.Bytes(w.Dispute[:])
	b.Time(w.WithdrawnAt)
	return b.Sum()
}

// Sign fills Signature using the complainant's private key.
func (w *Withdrawal) Sign(priv ed25519.PrivateKey) {
	w.Signature = ed25519.Sign(priv, w.CanonicalBytes())
}

// Verify reports whether Signature is a valid complainant signature over the
// withdrawal (length-checked before verifying). The complainant key is
// resolved by the Registry from the case's stored Opening.
func (w Withdrawal) Verify(complainant ed25519.PublicKey) bool {
	return len(complainant) == ed25519.PublicKeySize &&
		len(w.Signature) == ed25519.SignatureSize &&
		ed25519.Verify(complainant, w.CanonicalBytes(), w.Signature)
}

// leafID returns the withdrawal artifact's leaf hash over its canonical bytes
// plus its signature, under the leaf domain tag — the Store's dedup key for
// this artifact. Unexported: a withdrawal has no case-identity role of its
// own, so no public ID() is offered.
func (w Withdrawal) leafID() DisputeID {
	b := canon.New(domainID)
	b.Bytes(w.CanonicalBytes())
	b.Bytes(w.Signature)
	return DisputeID(sha256.Sum256(b.Sum()))
}

// clone returns a deep copy whose signature shares no memory with w.
func (w Withdrawal) clone() Withdrawal {
	w.Signature = append([]byte(nil), w.Signature...)
	return w
}
