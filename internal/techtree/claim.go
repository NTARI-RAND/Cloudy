package techtree

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Domain tags. One distinct tag per signed role and one for the artifact
// leaf-ID derivation, per canon's domain-separation rule: a techtree signature
// is not transferable to any other message type or platform tag, and a leaf-ID
// preimage can never double as a signing payload. v0 is unstable — the byte
// layout may change without compatibility guarantees.
const (
	domainClaim     = "cloudy/techtree/claim/v0"     // Claim signatures
	domainReference = "cloudy/techtree/reference/v0" // Reference (edge) signatures
	domainID        = "cloudy/techtree/id/v0"        // artifact leaf-ID derivation (hash role)
	domainChain     = "cloudy/techtree/chain/v0"     // append-only log chain fold
)

// ClaimID is a claim's identity: the [32]byte leaf ID of the claim
// (Claim.ID()). The zero value is invalid.
type ClaimID [32]byte

// ClaimKind is the closed set of claim types. It is a small enum, never free
// text, so no PII or narrative can ride in the "kind": a maker's product spec,
// an empirical fact, or a technique. Extending the set is a deliberate protocol
// change, not a user input.
type ClaimKind string

const (
	KindFact        ClaimKind = "fact"         // an empirical observation
	KindTechnique   ClaimKind = "technique"    // a method / how-to that may build on facts
	KindProductSpec ClaimKind = "product_spec" // a maker's product claim (the market bridge)
)

func validKind(k ClaimKind) bool {
	return k == KindFact || k == KindTechnique || k == KindProductSpec
}

// Claim is a member's single-signed, anchored assertion. Its field set is
// closed — no free-text field — so the commons holds only structural facts and
// hashes; the inputs/method/result narratives live member-local (the Locker),
// and the commons carries only their SHA-256. A claim is a MONOLOGUE (one
// claimant, one seal), unlike record.Entry's dual-sealed dialog: knowledge is
// asserted publicly and answered by OTHER members' claims and references, not
// by a countersignature.
type Claim struct {
	Platform   string            // platform this claim is bound to; inside CanonicalBytes (non-portable)
	Claimant   ed25519.PublicKey // the member asserting it; signs it
	Kind       ClaimKind         // fact | technique | product_spec
	InputsHash [32]byte          // SHA-256 of the member-local inputs narrative; text never enters the commons
	MethodHash [32]byte          // SHA-256 of the member-local method narrative
	ResultHash [32]byte          // SHA-256 of the member-local result narrative
	Nonce      [32]byte          // random; makes textually identical claims distinct and re-anchor detectable
	AssertedAt time.Time         // UTC; canon drops location and monotonic components
	Signature  []byte            // ed25519 by Claimant; excluded from CanonicalBytes
}

// NewClaim builds an unsigned claim bound to platform, drawing Nonce from
// crypto/rand. It owns a copy of the claimant key so a caller mutating its
// buffer afterward cannot alter the claim. The three hashes are computed
// member-side (see HashNarrative) from content that never enters this package.
func NewClaim(platform string, claimant ed25519.PublicKey, kind ClaimKind, inputs, method, result [32]byte, at time.Time) (Claim, error) {
	if platform == "" {
		return Claim{}, errors.New("techtree: platform must be set")
	}
	if len(claimant) != ed25519.PublicKeySize {
		return Claim{}, errors.New("techtree: claimant key is malformed")
	}
	if !validKind(kind) {
		return Claim{}, fmt.Errorf("techtree: unknown claim kind %q", kind)
	}
	c := Claim{
		Platform:   platform,
		Claimant:   append(ed25519.PublicKey(nil), claimant...),
		Kind:       kind,
		InputsHash: inputs,
		MethodHash: method,
		ResultHash: result,
		AssertedAt: at,
	}
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return Claim{}, fmt.Errorf("techtree: drawing nonce: %w", err)
	}
	return c, nil
}

// HashNarrative digests a member-local narrative (inputs, method, or result
// text) under the claim domain so callers derive the three hashes uniformly.
// The bytes are consumed into the digest and never retained — this package
// never holds narrative content.
func HashNarrative(narrative []byte) [32]byte {
	return sha256.Sum256(canon.New(domainClaim).Bytes(narrative).Sum())
}

// CanonicalBytes returns the deterministic signing payload (claim domain tag)
// with Signature excluded.
func (c Claim) CanonicalBytes() []byte {
	b := canon.New(domainClaim)
	b.String(c.Platform)
	b.Bytes(c.Claimant)
	b.String(string(c.Kind))
	b.Bytes(c.InputsHash[:])
	b.Bytes(c.MethodHash[:])
	b.Bytes(c.ResultHash[:])
	b.Bytes(c.Nonce[:])
	b.Time(c.AssertedAt)
	return b.Sum()
}

// Sign signs the claim with the claimant's private key; it errors if the key
// does not derive the Claimant public key, so signing a claim you did not
// author is inexpressible.
func (c *Claim) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("techtree: signing key is malformed")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(c.Claimant) {
		return errors.New("techtree: signing key is not the claimant")
	}
	c.Signature = ed25519.Sign(priv, c.CanonicalBytes())
	return nil
}

// Verify reports whether the claim is well-formed and validly self-signed by
// its claimant. Length guards precede ed25519.Verify (a wrong-length key would
// otherwise panic).
func (c Claim) Verify() bool {
	if c.Platform == "" || !validKind(c.Kind) {
		return false
	}
	if len(c.Claimant) != ed25519.PublicKeySize || len(c.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(c.Claimant, c.CanonicalBytes(), c.Signature)
}

// ID returns the claim's leaf hash (id domain tag, over canonical bytes plus
// the seal) — the value references and edges carry. A claim must be signed
// before its ID is meaningful.
func (c Claim) ID() ClaimID {
	b := canon.New(domainID)
	b.String("claim")
	b.Bytes(c.CanonicalBytes())
	b.Bytes(c.Signature)
	return ClaimID(sha256.Sum256(b.Sum()))
}
