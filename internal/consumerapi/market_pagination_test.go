package consumerapi

import (
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/market"
)

func TestMarketplaceBrowsePageBounds(t *testing.T) {
	s := browseServer(t)
	prefix := hx(s.logID[:]) + ":"
	for i := 0; i < 103; i++ {
		browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	}
	for _, tc := range []struct {
		query string
		want  int
		next  any
	}{
		{"?category=computer", 103, nil},
		{"?category=computer&cursor=0", 50, prefix + "50"},
		{"?category=computer&limit=100", 100, prefix + "100"},
		{"?category=computer&limit=100&cursor=" + prefix + "100", 3, nil},
		{"?category=computer&limit=1&cursor=" + prefix + "103", 0, nil},
	} {
		t.Run(tc.query, func(t *testing.T) {
			ids, page := browseIDs(t, s, tc.query)
			if len(ids) != tc.want {
				t.Fatalf("got %d offers, want %d", len(ids), tc.want)
			}
			if page["next_cursor"] != tc.next {
				t.Fatalf("next cursor = %v, want %v", page["next_cursor"], tc.next)
			}
		})
	}
}
