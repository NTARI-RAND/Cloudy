package consumerapi

import (
	"fmt"
	"github.com/NTARI-RAND/Cloudy/internal/techtree"
	"strings"
	"testing"
)

// Catches wrong direction/kind filters, skipped edges, repeated edges, and broken signed exports.
func TestReferenceDiscoveryPages(t *testing.T) {
	f := referenceFixture(t)
	for _, direction := range []string{"inbound", "outbound"} {
		t.Run(direction, func(t *testing.T) {
			want := f.incoming
			if direction == "outbound" {
				want = f.outgoing
			}
			got := collectEdges(t, f, direction)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("edge set/order: %v, want %v", got, want)
			}
		})
	}
	for i, kind := range []string{"cites", "builds_on", "reproduces", "refutes", "contests"} {
		page := readEdges(t, f.h, claimsPath+f.claim+"/references?direction=inbound&kind="+kind)
		if len(page.References) != 1 || page.References[0].ReferenceID != f.incoming[i] || page.NextCursor != "" {
			t.Fatalf("kind %s filter incorrect", kind)
		}
	}
}

func TestReferenceDiscoveryValidation(t *testing.T) {
	f := referenceFixture(t)
	base := claimsPath + f.claim + "/references"
	for _, query := range []string{"", "?direction=both", "?direction=inbound&kind=unknown", "?direction=inbound&kind=", "?direction=inbound&cursor=-1", "?direction=inbound&cursor=abc", "?direction=inbound&cursor=1.5", "?direction=inbound&cursor=999999999999999999999999", "?direction=inbound&cursor=9999", "?direction=inbound&limit=0", "?direction=inbound&limit=101", "?direction=inbound&limit=no", "?direction=inbound&limit=", "?direction=inbound&direction=outbound"} {
		rec, _ := do(t, f.h, "GET", base+query, nil)
		if rec.Code != 400 {
			t.Errorf("%s: got %d, want 400", query, rec.Code)
		}
	}
	for _, tc := range []struct {
		id     string
		status int
	}{{"bad", 400}, {strings.Repeat("00", 32), 404}} {
		rec, _ := do(t, f.h, "GET", claimsPath+tc.id+inboundPath, nil)
		if rec.Code != tc.status {
			t.Errorf("id %s: got %d, want %d", tc.id, rec.Code, tc.status)
		}
	}
}

func TestReferenceDiscoveryEmptyAndAppend(t *testing.T) {
	f := referenceFixture(t)
	empty := readEdges(t, f.h, claimsPath+f.from+inboundPath)
	if len(empty.References) != 0 || empty.NextCursor != "" {
		t.Fatal("empty result incorrect")
	}
	base := claimsPath + f.claim + "/references?direction=inbound&limit=1"
	first := readEdges(t, f.h, base)
	added := postEdge(t, f.h, f.from, f.claim, techtree.RefCites)
	want := append(append([]string{}, f.incoming[1:]...), added)
	var got []string
	cursor := first.NextCursor
	for requests := 0; requests < 10; requests++ {
		page := readEdges(t, f.h, base+"&cursor="+cursor)
		for _, r := range page.References {
			got = append(got, r.ReferenceID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("append shifted cursor: got %v want %v", got, want)
	}
}

func TestReferenceDiscoveryBounds(t *testing.T) {
	f := referenceFixture(t)
	for i := 0; i < 100; i++ {
		postEdge(t, f.h, f.from, f.claim, techtree.RefCites)
	}
	base := claimsPath + f.claim + inboundPath
	for _, tc := range []struct {
		query string
		count int
	}{{"", 50}, {"&limit=100", 100}} {
		page := readEdges(t, f.h, base+tc.query)
		if len(page.References) != tc.count || page.NextCursor == "" {
			t.Fatalf("page bounds: got %d want %d", len(page.References), tc.count)
		}
	}
}
