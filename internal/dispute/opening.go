package dispute

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Domain tags. One distinct tag per message role and one for the artifact
// leaf-ID derivation, per canon's domain-separation rule: a dispute signature
// is not transferable to any other message type or platform tag, and a leaf-ID
// preimage can never double as a signing payload. v0 is unstable — the byte
// layout may change without compatibility guarantees.
const (
	domainOpening    = "cloudy/dispute/opening/v0"    // Opening signatures (signature role)
	domainRuling     = "cloudy/dispute/ruling/v0"     // Ruling signatures (signature role)
	domainWithdrawal = "cloudy/dispute/withdrawal/v0" // Withdrawal signatures (signature role)
	domainID         = "cloudy/dispute/id/v0"         // artifact leaf-ID derivation (hash role)
)

// DisputeID is a case's identity: the [32]byte leaf ID of its Opening
// (Opening.ID()). It is also the leaf-ID type returned by every artifact's
// ID(); the zero value is invalid.
type DisputeID [32]byte

// ExchangeRef is an opaque 32-byte carrier of the disputed record entry's leaf
// ID (record.Entry.ID()). Conversion from the record layer's value happens
// only at the composition root, exactly like economy.Spend.ExchangeHash and
// covenant.ExchangeRef; dispute never parses or resolves it, and the zero
// value is invalid.
type ExchangeRef [32]byte

// Opening is a complainant's signed assertion that a sealed exchange went
// wrong. Its field set is closed — no free text — so no PII or narrative
// conduit exists in the commons: the only member-authored narrative is the
// reason text, which lives member-local, and the commons carries only its
// SHA-256 in ReasonHash (mirrors covenant.CommentHash).
type Opening struct {
	Platform    string            // platform this opening is bound to; inside CanonicalBytes
	Complainant ed25519.PublicKey // who opens the case; signs it; must differ from Respondent
	Respondent  ed25519.PublicKey // the counterparty the case is against
	Exchange    ExchangeRef       // the disputed record entry's leaf ID; zero is invalid
	ReasonHash  [32]byte          // SHA-256 of the member-local reason text; the text never enters the commons
	Nonce       [32]byte          // random; makes identical grievances distinct and double-open detectable
	OpenedAt    time.Time         // UTC; canon drops location and monotonic components
	Signature   []byte            // ed25519 by Complainant; excluded from CanonicalBytes
}

// NewOpening builds an unsigned Opening, drawing Nonce from crypto/rand. It
// rejects malformed or equal complainant/respondent keys and a zero exchange
// reference. The returned Opening owns copies of the key bytes, so a caller
// mutating its buffers afterward cannot alter the opening.
func NewOpening(platform string, complainant, respondent ed25519.PublicKey, exchange ExchangeRef, reasonHash [32]byte, at time.Time) (Opening, error) {
	if len(complainant) != ed25519.PublicKeySize {
		return Opening{}, errors.New("dispute: complainant key is malformed")
	}
	if len(respondent) != ed25519.PublicKeySize {
		return Opening{}, errors.New("dispute: respondent key is malformed")
	}
	if bytes.Equal(complainant, respondent) {
		return Opening{}, errors.New("dispute: complainant and respondent must be distinct members")
	}
	if exchange == (ExchangeRef{}) {
		return Opening{}, errors.New("dispute: zero exchange reference")
	}
	o := Opening{
		Platform:    platform,
		Complainant: append(ed25519.PublicKey(nil), complainant...),
		Respondent:  append(ed25519.PublicKey(nil), respondent...),
		Exchange:    exchange,
		ReasonHash:  reasonHash,
		OpenedAt:    at,
	}
	if _, err := rand.Read(o.Nonce[:]); err != nil {
		return Opening{}, fmt.Errorf("dispute: drawing nonce: %w", err)
	}
	return o, nil
}

// CanonicalBytes returns the deterministic signing payload (canon encoder,
// domain tag "cloudy/dispute/opening/v0") with Signature excluded; a signing
// payload only, never an export or interchange format. Field order is fixed:
// platform, complainant, respondent, exchange, reasonHash, nonce, openedAt.
func (o Opening) CanonicalBytes() []byte {
	b := canon.New(domainOpening)
	b.String(o.Platform)
	b.Bytes(o.Complainant)
	b.Bytes(o.Respondent)
	b.Bytes(o.Exchange[:])
	b.Bytes(o.ReasonHash[:])
	b.Bytes(o.Nonce[:])
	b.Time(o.OpenedAt)
	return b.Sum()
}

// Sign fills Signature using the complainant's private key. It errors if priv
// does not derive the Complainant key, so signing an opening in another
// member's name is inexpressible.
func (o *Opening) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("dispute: signing key is malformed")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, o.Complainant) {
		return errors.New("dispute: signing key is not the complainant")
	}
	o.Signature = ed25519.Sign(priv, o.CanonicalBytes())
	return nil
}

// Verify reports whether Complainant and Respondent are distinct well-formed
// keys, the exchange reference is non-zero, and Signature is a valid
// complainant signature (length-checked before verifying).
func (o Opening) Verify() bool {
	if len(o.Complainant) != ed25519.PublicKeySize || len(o.Respondent) != ed25519.PublicKeySize {
		return false
	}
	if bytes.Equal(o.Complainant, o.Respondent) {
		return false
	}
	if o.Exchange == (ExchangeRef{}) {
		return false
	}
	if len(o.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(o.Complainant, o.CanonicalBytes(), o.Signature)
}

// ID returns the case identity: the artifact leaf hash over the opening's
// canonical bytes plus its signature, under the leaf domain tag — the same
// discipline as record.Entry.ID(). Because Nonce is inside the canonical
// bytes, a genuine re-dispute after a terminal state (a fresh Opening with a
// fresh nonce) yields a distinct DisputeID.
func (o Opening) ID() DisputeID {
	b := canon.New(domainID)
	b.Bytes(o.CanonicalBytes())
	b.Bytes(o.Signature)
	return DisputeID(sha256.Sum256(b.Sum()))
}

// clone returns a deep copy whose key and signature slices share no memory
// with o, so an admitted opening can never be mutated through a caller's
// slice.
func (o Opening) clone() Opening {
	o.Complainant = append(ed25519.PublicKey(nil), o.Complainant...)
	o.Respondent = append(ed25519.PublicKey(nil), o.Respondent...)
	o.Signature = append([]byte(nil), o.Signature...)
	return o
}
