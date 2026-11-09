package consumerapi

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/market"
)

// A stale position must not silently skip new offers after the catalogue restarts.
func TestMarketplaceBrowseRejectsCursorFromPreviousInstance(t *testing.T) {
	original := browseServer(t)
	for i := 0; i < 2; i++ {
		browseListing(t, original, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	}
	_, first := browseIDs(t, original, "?category=computer&limit=1")
	cursor, ok := first["next_cursor"].(string)
	if !ok || cursor == "" {
		t.Fatal("first page has no continuation token")
	}
	restarted := browseServer(t)
	var want []string
	for i := 0; i < 3; i++ {
		want = append(want, browseListing(t, restarted, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true}))
	}
	rec, _ := do(t, restarted.Handler(), http.MethodGet,
		"/api/v1/market/listings?category=computer&limit=1&cursor="+url.QueryEscape(cursor), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("stale cursor returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	got, _ := browseIDs(t, restarted, "?category=computer&cursor=0")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh traversal = %v, want all new offers %v", got, want)
	}
}

// Instance binding must not bypass numeric or catalogue-bound validation.
func TestMarketplaceBrowseRejectsMalformedInstanceCursor(t *testing.T) {
	s := browseServer(t)
	browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	prefix := hx(s.logID[:]) + ":"
	for _, cursor := range []string{
		"1", "00", prefix, prefix + "-1", prefix + "+1", prefix + " 1",
		prefix + "1.0", prefix + "1:0", prefix + "999999999999999999999999",
		prefix + "2", "wrong-instance:0",
	} {
		t.Run(cursor, func(t *testing.T) {
			rec, _ := do(t, s.Handler(), http.MethodGet,
				"/api/v1/market/listings?category=computer&cursor="+url.QueryEscape(cursor), nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("cursor %q returned %d, want 400", cursor, rec.Code)
			}
		})
	}
}
