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

// RefID is a reference's identity: the [32]byte leaf ID of the reference
// (Reference.ID()). The zero value is invalid.
type RefID [32]byte

// RefKind is the closed set of typed edges between claims. A reference is a
// member's single-signed assertion drawn FROM one of their own claims TO
// another claim.
type RefKind string

const (
	// RefBuildsOn: From structurally depends on / extends To (a technique
	// builds on a fact). These edges MUST stay acyclic — knowledge accretes,
	// it does not depend on itself in a loop.
	RefBuildsOn RefKind = "builds_on"
	// RefCites: From references To as supporting material. Not structural, not
	// cycle-constrained.
	RefCites RefKind = "cites"
	// RefContests: From asserts To is wrong or disputed. A contest is a new
	// claim (From) pointing at the contested claim (To) — a visible annotation,
	// never an erasure.
	RefContests RefKind = "contests"
	// RefReproduces: From is an independent reproduction that SUPPORTS To.
	RefReproduces RefKind = "reproduces"
	// RefRefutes: From is an independent reproduction that FAILS to support To.
	RefRefutes RefKind = "refutes"
)

func validRefKind(k RefKind) bool {
	switch k {
	case RefBuildsOn, RefCites, RefContests, RefReproduces, RefRefutes:
		return true
	default:
		return false
	}
}

// Reference is a typed, single-signed edge From one claim To another. The
// asserter signs it; the Tree enforces at insert time that the asserter is the
// claimant of the From claim, so no member can forge a citation "from" someone
// else's claim.
type Reference struct {
	Platform   string            // platform this edge is bound to; inside CanonicalBytes
	Asserter   ed25519.PublicKey // who draws the edge; must be the claimant of From; signs it
	Kind       RefKind           // builds_on | cites | contests | reproduces | refutes
	From       ClaimID           // the claim making the reference
	To         ClaimID           // the referenced claim; MUST differ from From (no self-edge)
	Nonce      [32]byte          // random; makes identical edges distinct and re-draw detectable
	AssertedAt time.Time         // UTC
	Signature  []byte            // ed25519 by Asserter; excluded from CanonicalBytes
}

// NewReference builds an unsigned edge, drawing Nonce from crypto/rand. It
// rejects a malformed asserter key, an unknown kind, and a self-edge
// (From == To). Existence of From/To and the asserter-owns-From rule are
// enforced by the Tree at insert time (this constructor cannot see the graph).
func NewReference(platform string, asserter ed25519.PublicKey, kind RefKind, from, to ClaimID, at time.Time) (Reference, error) {
	if platform == "" {
		return Reference{}, errors.New("techtree: platform must be set")
	}
	if len(asserter) != ed25519.PublicKeySize {
		return Reference{}, errors.New("techtree: asserter key is malformed")
	}
	if !validRefKind(kind) {
		return Reference{}, fmt.Errorf("techtree: unknown reference kind %q", kind)
	}
	if from == to {
		return Reference{}, errors.New("techtree: a reference cannot point a claim at itself")
	}
	r := Reference{
		Platform:   platform,
		Asserter:   append(ed25519.PublicKey(nil), asserter...),
		Kind:       kind,
		From:       from,
		To:         to,
		AssertedAt: at,
	}
	if _, err := rand.Read(r.Nonce[:]); err != nil {
		return Reference{}, fmt.Errorf("techtree: drawing nonce: %w", err)
	}
	return r, nil
}

// CanonicalBytes returns the deterministic signing payload (reference domain
// tag) with Signature excluded.
func (r Reference) CanonicalBytes() []byte {
	b := canon.New(domainReference)
	b.String(r.Platform)
	b.Bytes(r.Asserter)
	b.String(string(r.Kind))
	b.Bytes(r.From[:])
	b.Bytes(r.To[:])
	b.Bytes(r.Nonce[:])
	b.Time(r.AssertedAt)
	return b.Sum()
}

// Sign signs the edge with the asserter's private key; it errors unless the key
// derives the Asserter public key.
func (r *Reference) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("techtree: signing key is malformed")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(r.Asserter) {
		return errors.New("techtree: signing key is not the asserter")
	}
	r.Signature = ed25519.Sign(priv, r.CanonicalBytes())
	return nil
}

// Verify reports whether the edge is well-formed and validly self-signed by its
// asserter.
func (r Reference) Verify() bool {
	if r.Platform == "" || !validRefKind(r.Kind) || r.From == r.To {
		return false
	}
	if len(r.Asserter) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(r.Asserter, r.CanonicalBytes(), r.Signature)
}

// ID returns the edge's leaf hash (id domain tag, over canonical bytes plus the
// seal).
func (r Reference) ID() RefID {
	b := canon.New(domainID)
	b.String("reference")
	b.Bytes(r.CanonicalBytes())
	b.Bytes(r.Signature)
	return RefID(sha256.Sum256(b.Sum()))
}
