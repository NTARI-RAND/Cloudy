package market

import (
	"crypto/ed25519"
	"errors"
)

// ListingQuery selects listings, never sales, in catalogue append order.
// Rails matches ANY selected rail; an empty set imposes no rail filter.
// Start is a catalogue log position. Limit zero preserves unpaged traversal.
// Like the other catalogue methods, Browse requires external synchronization.
type ListingQuery struct {
	Category Category
	Maker    ed25519.PublicKey
	Rails    AcceptedRails
	Start    int
	Limit    int
}

// ListingPage contains at most Limit ids. Next is zero at exhaustion, otherwise
// the append position following the last returned listing. Pages are live,
// not a frozen export; appends do not move existing catalogue positions.
type ListingPage struct {
	IDs  []ListingID
	Next int
}

// Browse scans without copying the log or building the complete matching set.
// Sparse filters can still scan the remaining history; storage for a bounded
// page grows with its result count, not with unrelated listings or sales.
func (c *Catalog) Browse(q ListingQuery) (ListingPage, error) {
	if q.Start < 0 || q.Start > len(c.log) || q.Limit < 0 {
		return ListingPage{}, errors.New("market: invalid listing page bounds")
	}
	page := ListingPage{}
	for pos := q.Start; pos < len(c.log); pos++ {
		l := c.log[pos].Listing
		if l == nil || !q.matches(*l) {
			continue
		}
		if q.Limit > 0 && len(page.IDs) == q.Limit {
			return page, nil
		}
		page.IDs = append(page.IDs, l.ID())
		page.Next = pos + 1
	}
	page.Next = 0
	return page, nil
}

func (q ListingQuery) matches(l Listing) bool {
	if l.Category != q.Category || (len(q.Maker) > 0 && !l.Maker.Equal(q.Maker)) {
		return false
	}
	return !q.Rails.Valid() || (q.Rails.Fiat && l.Rails.Fiat) || (q.Rails.MemberCredit && l.Rails.MemberCredit)
}

// SalesCount returns provenance depth without copying the exchange history.
func (c *Catalog) SalesCount(id ListingID) int { return len(c.sales[id]) }
