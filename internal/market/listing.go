package market

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
// leaf-ID derivation, per canon's domain-separation rule. v0 is unstable.
const (
	domainListing = "cloudy/market/listing/v0" // Listing signatures
	domainID      = "cloudy/market/id/v0"      // artifact leaf-ID derivation (hash role)
	domainChain   = "cloudy/market/chain/v0"   // append-only catalog chain fold
)

// SpecRef is the opaque [32]byte id of the product-spec CLAIM anchored in the
// techtree (a techtree.ClaimID of Kind product_spec). The composition root sets
// it; market never resolves it — same discipline as dispute.ExchangeRef.
type SpecRef [32]byte

// ExchangeRef is the opaque [32]byte id of a sealed record entry (a completed
// exchange). A listing's recorded sales are ExchangeRefs; per-product LBTAS is
// the covenant's distribution grouped over them, joined at the composition root.
type ExchangeRef [32]byte

// ListingID is a listing's identity: the [32]byte leaf id of the listing.
type ListingID [32]byte

// Listing is a maker's single-signed offer of a product in an allowed category.
// Its field set is closed — no free text — so the commons holds only structural
// facts and the SpecRef; the product name, copy, and images live member-local
// (the Locker). Platform is bound in (non-portable).
type Listing struct {
	Platform string            // platform this listing is bound to; inside CanonicalBytes
	Maker    ed25519.PublicKey // the member offering the product; signs it
	Category Category          // an allowlisted hardware category (node-class taxonomy)
	Spec     SpecRef           // the techtree product_spec claim id; the advertised specs are a contestable claim
	Rails    AcceptedRails     // which settlement rails this listing accepts (>= 1)
	Nonce    [32]byte          // random; makes textually identical listings distinct and re-list detectable
	ListedAt time.Time         // UTC

	Signature []byte // ed25519 by Maker; excluded from CanonicalBytes
}

// NewListing builds an unsigned listing, drawing Nonce from crypto/rand. It
// rejects an empty platform, a malformed maker key, an out-of-allowlist
// category, a zero SpecRef (a listing MUST point at an anchored spec claim), and
// an empty rail set. It owns a copy of the maker key.
func NewListing(platform string, maker ed25519.PublicKey, cat Category, spec SpecRef, rails AcceptedRails, at time.Time) (Listing, error) {
	if platform == "" {
		return Listing{}, errors.New("market: platform must be set")
	}
	if len(maker) != ed25519.PublicKeySize {
		return Listing{}, errors.New("market: maker key is malformed")
	}
	if !validCategory(cat) {
		return Listing{}, fmt.Errorf("market: category %q is not in the hardware allowlist", cat)
	}
	if spec == (SpecRef{}) {
		return Listing{}, errors.New("market: listing must reference a product-spec claim (zero SpecRef)")
	}
	if !rails.Valid() {
		return Listing{}, errors.New("market: listing must accept at least one settlement rail")
	}
	l := Listing{
		Platform: platform,
		Maker:    append(ed25519.PublicKey(nil), maker...),
		Category: cat,
		Spec:     spec,
		Rails:    rails,
		ListedAt: at,
	}
	if _, err := rand.Read(l.Nonce[:]); err != nil {
		return Listing{}, fmt.Errorf("market: drawing nonce: %w", err)
	}
	return l, nil
}

// CanonicalBytes returns the deterministic signing payload (listing domain tag)
// with Signature excluded.
func (l Listing) CanonicalBytes() []byte {
	b := canon.New(domainListing)
	b.String(l.Platform)
	b.Bytes(l.Maker)
	b.String(string(l.Category))
	b.Bytes(l.Spec[:])
	b.Bytes([]byte{l.Rails.canonByte()})
	b.Bytes(l.Nonce[:])
	b.Time(l.ListedAt)
	return b.Sum()
}

// Sign signs the listing with the maker's private key; it errors unless the key
// derives the Maker public key.
func (l *Listing) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("market: signing key is malformed")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(l.Maker) {
		return errors.New("market: signing key is not the maker")
	}
	l.Signature = ed25519.Sign(priv, l.CanonicalBytes())
	return nil
}

// Verify reports whether the listing is well-formed and validly self-signed by
// its maker. Length guards precede ed25519.Verify.
func (l Listing) Verify() bool {
	if l.Platform == "" || !validCategory(l.Category) || l.Spec == (SpecRef{}) || !l.Rails.Valid() {
		return false
	}
	if len(l.Maker) != ed25519.PublicKeySize || len(l.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(l.Maker, l.CanonicalBytes(), l.Signature)
}

// ID returns the listing's leaf hash (id domain tag, over canonical bytes plus
// the seal).
func (l Listing) ID() ListingID {
	b := canon.New(domainID)
	b.String("listing")
	b.Bytes(l.CanonicalBytes())
	b.Bytes(l.Signature)
	return ListingID(sha256.Sum256(b.Sum()))
}
