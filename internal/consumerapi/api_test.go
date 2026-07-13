package consumerapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/market"
	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

const platform = "cloudy-test"

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	s, err := NewServer(platform)
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func key(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func do(t *testing.T, h http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

// registerMember drives the real self-signed registration flow.
func registerMember(t *testing.T, h http.Handler, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	// Reproduce the server's register challenge to sign it.
	s, _ := NewServer(platform)
	sig := ed25519.Sign(priv, s.registerChallenge(pub))
	rec, _ := do(t, h, "POST", "/api/v1/members", registerRequest{
		PublicKey: hex.EncodeToString(pub),
		Signature: hex.EncodeToString(sig),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("register: code %d body %s", rec.Code, rec.Body.String())
	}
}

// anchorClaim builds, signs, and posts a claim; returns its id hex.
func anchorClaim(t *testing.T, h http.Handler, pub ed25519.PublicKey, priv ed25519.PrivateKey, kind techtree.ClaimKind, inputs, method, result string) string {
	t.Helper()
	c, err := techtree.NewClaim(platform, pub, kind,
		techtree.HashNarrative([]byte(inputs)),
		techtree.HashNarrative([]byte(method)),
		techtree.HashNarrative([]byte(result)),
		time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	rec, out := do(t, h, "POST", "/api/v1/claims", claimDTO{
		Platform: c.Platform, Claimant: hex.EncodeToString(c.Claimant), Kind: string(c.Kind),
		InputsHash: hex.EncodeToString(c.InputsHash[:]), MethodHash: hex.EncodeToString(c.MethodHash[:]),
		ResultHash: hex.EncodeToString(c.ResultHash[:]), Nonce: hex.EncodeToString(c.Nonce[:]),
		AssertedAtNs: c.AssertedAt.UnixNano(), Signature: hex.EncodeToString(c.Signature),
		Inputs: inputs, Method: method, Result: result,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("anchor claim: code %d body %s", rec.Code, rec.Body.String())
	}
	return out["claim_id"].(string)
}

func TestRegisterRequiresProofOfKey(t *testing.T) {
	h := newTestServer(t)
	pub, _ := key(1)
	_, wrongPriv := key(2)
	// Sign the challenge with the WRONG key → rejected.
	s, _ := NewServer(platform)
	badSig := ed25519.Sign(wrongPriv, s.registerChallenge(pub))
	rec, _ := do(t, h, "POST", "/api/v1/members", registerRequest{
		PublicKey: hex.EncodeToString(pub),
		Signature: hex.EncodeToString(badSig),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("register with wrong-key signature: code %d, want 401", rec.Code)
	}
}

func TestFullFlow(t *testing.T) {
	h := newTestServer(t)
	makerPub, makerPriv := key(1)
	buyerPub, buyerPriv := key(2)
	registerMember(t, h, makerPub, makerPriv)
	registerMember(t, h, buyerPub, buyerPriv)

	// Maker anchors a product_spec claim.
	specID := anchorClaim(t, h, makerPub, makerPriv, techtree.KindProductSpec,
		"NTARI Node One", "8-core ARM, 32GB, 2TB NVMe", "idle draw 6W")

	// GET the claim: structural + narrative from the Locker + zero weight.
	rec, out := do(t, h, "GET", "/api/v1/claims/"+specID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get claim: %d %s", rec.Code, rec.Body.String())
	}
	if out["kind"] != "product_spec" {
		t.Fatalf("claim kind = %v, want product_spec", out["kind"])
	}
	narr, _ := out["narrative"].(map[string]any)
	if narr == nil || narr["result"] != "idle draw 6W" {
		t.Fatalf("narrative not returned from Locker: %v", out["narrative"])
	}

	// Buyer authors their own fact claim, then CITES the maker's spec.
	buyerClaim := anchorClaim(t, h, buyerPub, buyerPriv, techtree.KindFact,
		"bought and measured", "kill-a-watt over 24h", "idle draw measured 6.2W")
	ref, _ := techtree.NewReference(platform, buyerPub, techtree.RefReproduces,
		decodeClaimID(t, buyerClaim), decodeClaimID(t, specID), time.Now().UTC())
	if err := ref.Sign(buyerPriv); err != nil {
		t.Fatal(err)
	}
	rrec, _ := do(t, h, "POST", "/api/v1/references", referenceDTO{
		Platform: ref.Platform, Asserter: hex.EncodeToString(ref.Asserter), Kind: string(ref.Kind),
		From: buyerClaim, To: specID, Nonce: hex.EncodeToString(ref.Nonce[:]),
		AssertedAtNs: ref.AssertedAt.UnixNano(), Signature: hex.EncodeToString(ref.Signature),
	})
	if rrec.Code != http.StatusCreated {
		t.Fatalf("add reference: %d %s", rrec.Code, rrec.Body.String())
	}

	// The spec claim now shows one reproduce in its citation weight.
	_, cout := do(t, h, "GET", "/api/v1/claims/"+specID, nil)
	wt, _ := cout["citation_weight"].(map[string]any)
	if wt == nil || wt["reproduces"].(float64) != 1 {
		t.Fatalf("citation weight reproduces = %v, want 1", wt)
	}

	// Maker lists the product (fiat + member credit), pointing at the spec claim.
	l, err := market.NewListing(platform, makerPub, market.CategoryComputer,
		market.SpecRef(decodeClaimID(t, specID)),
		market.AcceptedRails{Fiat: true, MemberCredit: true}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Sign(makerPriv); err != nil {
		t.Fatal(err)
	}
	lrec, lout := do(t, h, "POST", "/api/v1/market/listings", listingDTO{
		Platform: l.Platform, Maker: hex.EncodeToString(l.Maker), Category: string(l.Category),
		Spec: specID, AcceptFiat: true, AcceptCredit: true, Nonce: hex.EncodeToString(l.Nonce[:]),
		ListedAtNs: l.ListedAt.UnixNano(), Signature: hex.EncodeToString(l.Signature),
	})
	if lrec.Code != http.StatusCreated {
		t.Fatalf("create listing: %d %s", lrec.Code, lrec.Body.String())
	}
	listingID := lout["listing_id"].(string)

	// Browse the computer category → the listing is there.
	_, bout := do(t, h, "GET", "/api/v1/market/listings?category=computer", nil)
	listings, _ := bout["listings"].([]any)
	if len(listings) != 1 {
		t.Fatalf("browse computer: got %d listings, want 1", len(listings))
	}
	first, _ := listings[0].(map[string]any)
	if first["listing_id"] != listingID || first["accept_member_credit"] != true {
		t.Fatalf("listing view mismatch: %v", first)
	}

	// Standing endpoint returns an empty-but-valid distribution for the maker
	// (registered above; standing is empty — no sealed exchanges yet).
	makerMember := string(covenant.MemberIDFor(platform, makerPub))
	srec, sout := do(t, h, "GET", "/api/v1/members/"+makerMember+"/standing", nil)
	if srec.Code != http.StatusOK {
		t.Fatalf("standing: %d %s", srec.Code, srec.Body.String())
	}
	for rel, v := range sout["relations"].(map[string]any) {
		if v.(map[string]any)["harm"].(float64) != 0 {
			t.Fatalf("fresh member harm (%s) = %v, want 0", rel, v.(map[string]any)["harm"])
		}
	}
}

func TestUnregisteredClaimantRejected(t *testing.T) {
	h := newTestServer(t)
	pub, priv := key(9) // never registered
	c, _ := techtree.NewClaim(platform, pub, techtree.KindFact,
		techtree.HashNarrative([]byte("a")), techtree.HashNarrative([]byte("b")),
		techtree.HashNarrative([]byte("c")), time.Now().UTC())
	_ = c.Sign(priv)
	rec, _ := do(t, h, "POST", "/api/v1/claims", claimDTO{
		Platform: c.Platform, Claimant: hex.EncodeToString(c.Claimant), Kind: string(c.Kind),
		InputsHash: hex.EncodeToString(c.InputsHash[:]), MethodHash: hex.EncodeToString(c.MethodHash[:]),
		ResultHash: hex.EncodeToString(c.ResultHash[:]), Nonce: hex.EncodeToString(c.Nonce[:]),
		AssertedAtNs: c.AssertedAt.UnixNano(), Signature: hex.EncodeToString(c.Signature),
		Inputs: "a", Method: "b", Result: "c",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unregistered claimant: code %d, want 401", rec.Code)
	}
}

func TestNarrativeMustMatchSignedHash(t *testing.T) {
	h := newTestServer(t)
	pub, priv := key(3)
	registerMember(t, h, pub, priv)
	c, _ := techtree.NewClaim(platform, pub, techtree.KindFact,
		techtree.HashNarrative([]byte("real inputs")), techtree.HashNarrative([]byte("m")),
		techtree.HashNarrative([]byte("r")), time.Now().UTC())
	_ = c.Sign(priv)
	rec, _ := do(t, h, "POST", "/api/v1/claims", claimDTO{
		Platform: c.Platform, Claimant: hex.EncodeToString(c.Claimant), Kind: string(c.Kind),
		InputsHash: hex.EncodeToString(c.InputsHash[:]), MethodHash: hex.EncodeToString(c.MethodHash[:]),
		ResultHash: hex.EncodeToString(c.ResultHash[:]), Nonce: hex.EncodeToString(c.Nonce[:]),
		AssertedAtNs: c.AssertedAt.UnixNano(), Signature: hex.EncodeToString(c.Signature),
		Inputs: "TAMPERED inputs", Method: "m", Result: "r", // does not hash to the signed InputsHash
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched narrative: code %d, want 400", rec.Code)
	}
}

// helpers

func decodeClaimID(t *testing.T, h string) techtree.ClaimID {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad claim id hex %q", h)
	}
	var id techtree.ClaimID
	copy(id[:], b)
	return id
}
