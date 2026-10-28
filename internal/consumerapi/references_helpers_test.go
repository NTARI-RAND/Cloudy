package consumerapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

const claimsPath = "/api/v1/claims/"
const inboundPath = "/references?direction=inbound"

type edgeWire struct {
	ReferenceID  string `json:"reference_id"`
	Platform     string `json:"platform"`
	Asserter     string `json:"asserter"`
	Kind         string `json:"kind"`
	From         string `json:"from"`
	To           string `json:"to"`
	Nonce        string `json:"nonce"`
	AssertedAtNs string `json:"asserted_at_ns"`
	Signature    string `json:"signature"`
}

type edgeResponse struct {
	References []edgeWire `json:"references"`
	NextCursor string     `json:"next_cursor"`
}

type edgeFixture struct {
	h                  http.Handler
	claim, from, to    string
	incoming, outgoing []string
}

func referenceFixture(t *testing.T) edgeFixture {
	t.Helper()
	h := newTestServer(t)
	pub, priv := key(42)
	registerMember(t, h, pub, priv)
	ids := make([]string, 3)
	for i := range ids {
		ids[i] = anchorClaim(t, h, pub, priv, techtree.KindFact, "private inputs", "private method", "private result")
	}
	f := edgeFixture{h: h, claim: ids[0], from: ids[1], to: ids[2]}
	for _, kind := range []techtree.RefKind{techtree.RefCites, techtree.RefBuildsOn, techtree.RefReproduces, techtree.RefRefutes, techtree.RefContests} {
		f.incoming = append(f.incoming, postEdge(t, h, ids[1], ids[0], kind))
		f.outgoing = append(f.outgoing, postEdge(t, h, ids[0], ids[2], kind))
		postEdge(t, h, ids[1], ids[2], kind)
	}
	return f
}

func postEdge(t *testing.T, h http.Handler, from, to string, kind techtree.RefKind) string {
	t.Helper()
	pub, priv := key(42)
	ref, err := techtree.NewReference(platform, pub, kind, decodeClaimID(t, from), decodeClaimID(t, to), time.Unix(1700000000, 123456789).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = ref.Sign(priv); err != nil {
		t.Fatal(err)
	}
	rec, out := do(t, h, "POST", "/api/v1/references", referenceDTO{Platform: ref.Platform, Asserter: hex.EncodeToString(ref.Asserter), Kind: string(kind), From: from, To: to, Nonce: hex.EncodeToString(ref.Nonce[:]), AssertedAtNs: ref.AssertedAt.UnixNano(), Signature: hex.EncodeToString(ref.Signature)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("post edge: %d %s", rec.Code, rec.Body.String())
	}
	return out["reference_id"].(string)
}

func readEdges(t *testing.T, h http.Handler, path string) edgeResponse {
	t.Helper()
	rec, _ := do(t, h, "GET", path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get edges: %d %s", rec.Code, rec.Body.String())
	}
	var page edgeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.References == nil {
		t.Fatal("references must be an array")
	}
	if strings.Contains(rec.Body.String(), "private inputs") || strings.Contains(rec.Body.String(), "narrative") {
		t.Fatal("member-local narrative leaked")
	}
	for _, wire := range page.References {
		verifyExportedEdge(t, wire)
	}
	return page
}

func verifyExportedEdge(t *testing.T, wire edgeWire) {
	t.Helper()

	// Decode independently from the production export; verification catches missing signed fields.
	pub, err := hex.DecodeString(wire.Asserter)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(wire.Signature)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(wire.Nonce)
	if err != nil || len(nonce) != 32 {
		t.Fatal("bad nonce")
	}
	ns, err := strconv.ParseInt(wire.AssertedAtNs, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if ns != 1700000000123456789 {
		t.Fatalf("timestamp lost precision: %s", wire.AssertedAtNs)
	}
	ref := techtree.Reference{Platform: wire.Platform, Asserter: pub, Kind: techtree.RefKind(wire.Kind), From: decodeClaimID(t, wire.From), To: decodeClaimID(t, wire.To), AssertedAt: time.Unix(0, ns), Signature: sig}
	copy(ref.Nonce[:], nonce)
	id := ref.ID()
	if !ref.Verify() || hex.EncodeToString(id[:]) != wire.ReferenceID {
		t.Fatal("exported reference cannot be verified")
	}
	ref.Kind = techtree.RefKind("tampered")
	if ref.Verify() {
		t.Fatal("tampered artifact verifies")
	}
}

func collectEdges(t *testing.T, f edgeFixture, direction string) []string {
	t.Helper()
	base := claimsPath + f.claim + "/references?direction=" + direction + "&limit=2"
	var got []string
	cursor := ""
	for requests := 0; requests < 5; requests++ {
		page := readEdges(t, f.h, base+"&cursor="+cursor)
		if len(page.References) > 2 {
			t.Fatal("page exceeds limit")
		}
		for _, r := range page.References {
			got = append(got, r.ReferenceID)
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = page.NextCursor
	}
	return got
}
