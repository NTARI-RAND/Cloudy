package consumerapi

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/market"
	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

// The fixtures enter through signed HTTP writes, so filtering cannot rely on
// caller-supplied maker labels or bypass the real catalogue's invariants.
func browseListing(t *testing.T, s *Server, seed byte, category market.Category, rails market.AcceptedRails) string {
	t.Helper()
	pub, priv := key(seed)
	h := s.Handler()
	registerMember(t, h, pub, priv)
	specID := anchorClaim(t, h, pub, priv, techtree.KindProductSpec, "private specification", "test", "test")
	l, err := market.NewListing(platform, pub, category, market.SpecRef(decodeClaimID(t, specID)), rails, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Sign(priv); err != nil {
		t.Fatal(err)
	}
	rec, out := do(t, h, http.MethodPost, "/api/v1/market/listings", listingDTO{
		Platform: platform, Maker: hx(pub), Category: string(category), Spec: specID,
		AcceptFiat: rails.Fiat, AcceptCredit: rails.MemberCredit, Nonce: hx(l.Nonce[:]),
		ListedAtNs: l.ListedAt.UnixNano(), Signature: hx(l.Signature),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create listing: %d %s", rec.Code, rec.Body.String())
	}
	return out["listing_id"].(string)
}

func browseServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(platform)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func browseIDs(t *testing.T, s *Server, query string) ([]string, map[string]any) {
	t.Helper()
	rec, out := do(t, s.Handler(), http.MethodGet, "/api/v1/market/listings"+query, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("browse %s: %d %s", query, rec.Code, rec.Body.String())
	}
	rows, ok := out["listings"].([]any)
	if !ok {
		t.Fatalf("listings is not an array: %s", rec.Body.String())
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.(map[string]any)["listing_id"].(string))
	}
	return ids, out
}

// Catches ignoring any filter, applying rails as AND, or sorting by maker/time.
func TestMarketplaceBrowseFilters(t *testing.T) {
	s := browseServer(t)
	a := browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	b := browseListing(t, s, 2, market.CategoryComputer, market.AcceptedRails{MemberCredit: true})
	c := browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true, MemberCredit: true})
	_ = browseListing(t, s, 1, market.CategorySmartTV, market.AcceptedRails{Fiat: true})
	pub, _ := key(1)
	makerQuery := "?category=computer&maker="
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"?category=computer&rail=fiat", []string{a, c}},
		{"?category=computer&rail=member_credit", []string{b, c}},
		{"?category=computer&rail=fiat&rail=member_credit", []string{a, b, c}},
		{makerQuery + hx(pub) + "&rail=member_credit", []string{c}},
		{makerQuery + strings.ToUpper(hx(pub)), []string{a, c}},
		{makerQuery + strings.Repeat("00", ed25519.PublicKeySize), []string{}},
	} {
		t.Run(tc.query, func(t *testing.T) {
			got, _ := browseIDs(t, s, tc.query)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// Renaming or replacing a summary field must fail even if its field count stays nine.
func TestMarketplaceBrowseSummaryFields(t *testing.T) {
	s := browseServer(t)
	browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	_, page := browseIDs(t, s, "?category=computer&limit=1")
	row := page["listings"].([]any)[0].(map[string]any)
	fields := make([]string, 0, len(row))
	for field := range row {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	want := []string{"accept_fiat", "accept_member_credit", "category", "listed_at", "listing_id", "maker", "platform", "sales_count", "spec"}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("summary fields = %v, want %v", fields, want)
	}
}

// Catches cursors based on filtered offsets, counting sales as offers, missing
// continuation, duplicate pages, and leaking narrative in the summary.
func TestMarketplaceBrowsePagesAcrossSalesAndAppends(t *testing.T) {
	s := browseServer(t)
	a := browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	idBytes, _ := hex.DecodeString(a)
	var id market.ListingID
	copy(id[:], idBytes)
	if err := s.catalog.RecordSale(id, market.ExchangeRef{1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = browseListing(t, s, 1, market.CategorySmartTV, market.AcceptedRails{Fiat: true})
	b := browseListing(t, s, 2, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	first, page := browseIDs(t, s, "?category=computer&limit=1")
	if !reflect.DeepEqual(first, []string{a}) || page["next_cursor"] != "1" {
		t.Fatalf("first page: %v", page)
	}
	row := page["listings"].([]any)[0].(map[string]any)
	if row["sales_count"] != float64(1) || len(row) != 9 {
		t.Fatalf("summary fields changed: %v", row)
	}
	c := browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{MemberCredit: true})
	second, page := browseIDs(t, s, "?category=computer&limit=1&cursor=1")
	if !reflect.DeepEqual(second, []string{b}) || page["next_cursor"] != "4" {
		t.Fatalf("second page: %v", page)
	}
	last, page := browseIDs(t, s, "?category=computer&limit=1&cursor=4")
	if !reflect.DeepEqual(last, []string{c}) || page["next_cursor"] != nil {
		t.Fatalf("last page: %v", page)
	}
}

func TestMarketplaceBrowseLegacyAndEmptyCategory(t *testing.T) {
	s := browseServer(t)
	a := browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	ids, out := browseIDs(t, s, "?category=computer")
	if !reflect.DeepEqual(ids, []string{a}) || len(out) != 1 {
		t.Fatalf("legacy response changed: %v", out)
	}
	for _, query := range []string{"", "?category=", "?category=&limit=1", "?cursor=0"} {
		ids, _ := browseIDs(t, s, query)
		if len(ids) != 0 {
			t.Fatalf("empty category %q returned %v", query, ids)
		}
	}
}

// Catches accepting malformed/ambiguous queries or clamping invalid bounds.
func TestMarketplaceBrowseRejectsMalformedFilters(t *testing.T) {
	s := browseServer(t)
	const makerParameter = "maker="
	for _, query := range []string{
		"category=tomato", "category=computer&category=smart_tv", makerParameter, "maker=zz", makerParameter + strings.Repeat("ab", 31),
		makerParameter + strings.Repeat("ab", 33), "maker=aa&maker=bb", "rail=", "rail=credit", "rail=fiat,member_credit",
		"limit=", "limit=0", "limit=-1", "limit=101", "limit=1junk", "limit=%2B1", "limit=1&limit=2",
		"cursor=", "cursor=-1", "cursor=1.0", "cursor=1junk", "cursor=%201", "cursor=999999999999999999999999", "cursor=1", "cursor=0&cursor=0",
		"category=computer%ZZ",
	} {
		t.Run(query, func(t *testing.T) {
			rec, _ := do(t, s.Handler(), http.MethodGet, "/api/v1/market/listings?"+query, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestMarketplaceBrowsePageBounds(t *testing.T) {
	s := browseServer(t)
	for i := 0; i < 103; i++ {
		browseListing(t, s, 1, market.CategoryComputer, market.AcceptedRails{Fiat: true})
	}
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"?category=computer", 103},
		{"?category=computer&cursor=0", 50},
		{"?category=computer&limit=100", 100},
		{"?category=computer&limit=100&cursor=100", 3},
		{"?category=computer&limit=1&cursor=103", 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			ids, _ := browseIDs(t, s, tc.query)
			if len(ids) != tc.want {
				t.Fatalf("got %d offers, want %d", len(ids), tc.want)
			}
		})
	}
}

func BenchmarkMarketplaceBrowse(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			h := benchmarkMarketHandler(b, count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/market/listings?category=computer&limit=10", nil))
				if rec.Code != http.StatusOK {
					b.Fatal(rec.Code)
				}
			}
		})
	}
}

func benchmarkMarketHandler(b *testing.B, count int) http.Handler {
	b.Helper()
	s, err := NewServer(platform)
	if err != nil {
		b.Fatal(err)
	}
	pub, priv := key(1)
	for i := 0; i < count; i++ {
		l, err := market.NewListing(platform, pub, market.CategoryComputer, market.SpecRef{1}, market.AcceptedRails{Fiat: true}, time.Now())
		if err != nil {
			b.Fatal(err)
		}
		if err := l.Sign(priv); err != nil {
			b.Fatal(err)
		}
		if _, err := s.catalog.AddListing(l); err != nil {
			b.Fatal(err)
		}
	}
	return s.Handler()
}
