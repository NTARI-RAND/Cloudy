package market

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Catalog invariants.
var (
	ErrWrongPlatform  = errors.New("market: artifact platform does not match the catalog")
	ErrBadSignature   = errors.New("market: listing failed signature verification")
	ErrDuplicate      = errors.New("market: artifact already in the catalog")
	ErrUnknownListing = errors.New("market: sale references a listing not in the catalog")
	ErrZeroExchange   = errors.New("market: sale references a zero exchange")
	ErrEmptyPlatform  = errors.New("market: catalog platform must be set")
)

// Hash is the append-only chain head type.
type Hash [32]byte

// Sale records that a listing settled a completed exchange (the opaque leaf id
// of a sealed record entry). It is the link the composition root uses to group
// covenant assessments per product, and — for used goods — a listing's prior
// sales are its witnessed provenance. Not maker-signed: settlement happens on
// the fiat/credit rail elsewhere; the root records the resulting ExchangeRef.
type Sale struct {
	Listing    ListingID
	Exchange   ExchangeRef
	RecordedAt time.Time
}

func (s Sale) leaf() []byte {
	b := canon.New(domainID)
	b.String("sale")
	b.Bytes(s.Listing[:])
	b.Bytes(s.Exchange[:])
	b.Time(s.RecordedAt)
	return b.Sum()
}

// Item is one entry in the append-only catalog log: exactly one of Listing or
// Sale is non-nil. It is the unit of replay and of future witnessing.
type Item struct {
	Listing *Listing
	Sale    *Sale
}

// Catalog is an append-only, hash-chained store of listings and their recorded
// sales, scoped to one platform. Ordering is by append (listing time), never by
// any promotion or rank — there is deliberately no such field. Single-writer
// StandIn until the shared record witnessing lands.
type Catalog struct {
	platform string
	listings map[ListingID]Listing
	sales    map[ListingID][]ExchangeRef
	log      []Item
	head     Hash
}

// NewCatalog returns an empty catalog bound to platform.
func NewCatalog(platform string) (*Catalog, error) {
	if platform == "" {
		return nil, ErrEmptyPlatform
	}
	return &Catalog{
		platform: platform,
		listings: make(map[ListingID]Listing),
		sales:    make(map[ListingID][]ExchangeRef),
	}, nil
}

// Platform returns the platform this catalog is bound to.
func (c *Catalog) Platform() string { return c.platform }

// Head returns the current chain head (zero for an empty catalog).
func (c *Catalog) Head() Hash { return c.head }

func (c *Catalog) fold(leaf []byte) {
	b := canon.New(domainChain)
	b.Bytes(c.head[:])
	b.Bytes(leaf)
	c.head = Hash(sha256.Sum256(b.Sum()))
}

// AddListing verifies a listing, rejects a cross-platform or duplicate one, and
// appends it.
func (c *Catalog) AddListing(l Listing) (ListingID, error) {
	if l.Platform != c.platform {
		return ListingID{}, ErrWrongPlatform
	}
	if !l.Verify() {
		return ListingID{}, ErrBadSignature
	}
	id := l.ID()
	if _, ok := c.listings[id]; ok {
		return ListingID{}, ErrDuplicate
	}
	c.listings[id] = cloneListing(l)
	c.log = append(c.log, Item{Listing: cloneListingPtr(l)})
	c.fold(id[:])
	return id, nil
}

// RecordSale appends a completed exchange to a listing's sales. The listing must
// exist, the exchange must be non-zero, and the same exchange is not recorded
// twice for a listing.
func (c *Catalog) RecordSale(listing ListingID, exchange ExchangeRef, at time.Time) error {
	if _, ok := c.listings[listing]; !ok {
		return fmt.Errorf("%w: %x", ErrUnknownListing, listing[:6])
	}
	if exchange == (ExchangeRef{}) {
		return ErrZeroExchange
	}
	for _, e := range c.sales[listing] {
		if e == exchange {
			return ErrDuplicate
		}
	}
	s := Sale{Listing: listing, Exchange: exchange, RecordedAt: at}
	c.sales[listing] = append(c.sales[listing], exchange)
	c.log = append(c.log, Item{Sale: &s})
	c.fold(s.leaf())
	return nil
}

// Listing returns a copy of a stored listing and whether it exists.
func (c *Catalog) Listing(id ListingID) (Listing, bool) {
	l, ok := c.listings[id]
	if !ok {
		return Listing{}, false
	}
	return cloneListing(l), true
}

// SalesOf returns the exchange refs recorded against a listing, in append
// order. The composition root feeds these to the covenant to build the
// per-product LBTAS distribution, and they are the listing's provenance for
// secondary-market resale.
func (c *Catalog) SalesOf(id ListingID) []ExchangeRef {
	out := make([]ExchangeRef, len(c.sales[id]))
	copy(out, c.sales[id])
	return out
}

// ByCategory returns the ids of listings in a category, in APPEND ORDER —
// never by any rank or promotion (there is no such field; ordering by payment
// would be paid placement, which is off-architecture). A consumer applies its
// own legible ordering (e.g. covenant distribution, citation weight, recency).
func (c *Catalog) ByCategory(cat Category) []ListingID {
	var out []ListingID
	for _, it := range c.log {
		if it.Listing == nil {
			continue
		}
		if it.Listing.Category == cat {
			out = append(out, it.Listing.ID())
		}
	}
	return out
}

// Log returns the append-ordered log (defensive copies), for replay and
// witnessing.
func (c *Catalog) Log() []Item {
	out := make([]Item, len(c.log))
	for i, it := range c.log {
		if it.Listing != nil {
			out[i] = Item{Listing: cloneListingPtr(*it.Listing)}
		} else {
			s := *it.Sale
			out[i] = Item{Sale: &s}
		}
	}
	return out
}

// OpenLog rebuilds a catalog from an ordered log, re-verifying every listing and
// re-enforcing every invariant through the same Add path. A tampered, reordered,
// or forged log fails here.
func OpenLog(platform string, items []Item) (*Catalog, error) {
	c, err := NewCatalog(platform)
	if err != nil {
		return nil, err
	}
	for i, it := range items {
		switch {
		case it.Listing != nil && it.Sale != nil:
			return nil, fmt.Errorf("market: log item %d has both a listing and a sale", i)
		case it.Listing != nil:
			if _, err := c.AddListing(*it.Listing); err != nil {
				return nil, fmt.Errorf("market: replay listing at %d: %w", i, err)
			}
		case it.Sale != nil:
			if err := c.RecordSale(it.Sale.Listing, it.Sale.Exchange, it.Sale.RecordedAt); err != nil {
				return nil, fmt.Errorf("market: replay sale at %d: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("market: log item %d is empty", i)
		}
	}
	return c, nil
}

func cloneListing(l Listing) Listing {
	l.Maker = append(ed25519.PublicKey(nil), l.Maker...)
	l.Signature = append([]byte(nil), l.Signature...)
	return l
}

func cloneListingPtr(l Listing) *Listing { ll := cloneListing(l); return &ll }
