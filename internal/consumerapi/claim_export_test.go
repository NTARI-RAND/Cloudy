package consumerapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

// Deliberately decode the public file without production export/ingest DTOs.
// All fields needed by an offline verifier must come from the downloaded bytes.
func decodeExportedClaim(t *testing.T, body []byte) (techtree.Claim, string) {
	t.Helper()
	var file struct {
		ID         string `json:"claim_id"`
		Platform   string `json:"platform"`
		Claimant   string `json:"claimant"`
		Kind       string `json:"kind"`
		InputsHash string `json:"inputs_hash"`
		MethodHash string `json:"method_hash"`
		ResultHash string `json:"result_hash"`
		Nonce      string `json:"nonce"`
		At         string `json:"asserted_at_ns"`
		Signature  string `json:"signature"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatal(err)
	}
	decode := func(value string, size int) []byte {
		t.Helper()
		valueBytes, err := hex.DecodeString(value)
		if err != nil || len(valueBytes) != size {
			t.Fatalf("malformed %d-byte export field %q: %v", size, value, err)
		}
		return valueBytes
	}
	at, err := strconv.ParseInt(file.At, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	c := techtree.Claim{
		Platform: file.Platform, Claimant: ed25519.PublicKey(decode(file.Claimant, ed25519.PublicKeySize)),
		Kind: techtree.ClaimKind(file.Kind), AssertedAt: time.Unix(0, at).UTC(),
		Signature: decode(file.Signature, ed25519.SignatureSize),
	}
	copy(c.InputsHash[:], decode(file.InputsHash, 32))
	copy(c.MethodHash[:], decode(file.MethodHash, 32))
	copy(c.ResultHash[:], decode(file.ResultHash, 32))
	copy(c.Nonce[:], decode(file.Nonce, 32))
	return c, file.ID
}

func TestClaimExportVerifiesOfflineWithoutNarrative(t *testing.T) {
	h := newTestServer(t)
	pub, priv := key(61)
	registerMember(t, h, pub, priv)
	at := time.Date(2026, 10, 26, 18, 23, 45, 123456789, time.FixedZone("offset", -19800))
	narrative := "member-local address: do-not-export@example.test"
	c, err := techtree.NewClaim(platform, pub, techtree.KindFact,
		techtree.HashNarrative([]byte(narrative)), techtree.HashNarrative([]byte("private method")),
		techtree.HashNarrative([]byte("private result")), at)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	id := c.ID()
	idHex := hex.EncodeToString(id[:])
	rec, _ := do(t, h, "POST", "/api/v1/claims", claimDTO{
		Platform: c.Platform, Claimant: hex.EncodeToString(pub), Kind: string(c.Kind),
		InputsHash: hex.EncodeToString(c.InputsHash[:]), MethodHash: hex.EncodeToString(c.MethodHash[:]),
		ResultHash: hex.EncodeToString(c.ResultHash[:]), Nonce: hex.EncodeToString(c.Nonce[:]),
		AssertedAtNs: c.AssertedAt.UnixNano(), Signature: hex.EncodeToString(c.Signature),
		Inputs: narrative, Method: "private method", Result: "private result",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("anchor: %d %s", rec.Code, rec.Body.String())
	}
	before, _ := do(t, h, "GET", "/api/v1/claims/"+idHex, nil)
	export, _ := do(t, h, "GET", "/api/v1/claims/"+idHex+"/export", nil)
	if export.Code != http.StatusOK {
		t.Fatalf("export: %d %s", export.Code, export.Body.String())
	}
	if export.Header().Get("Content-Type") != "application/json" || export.Header().Get("Content-Disposition") != `attachment; filename="claim-`+idHex+`.json"` {
		t.Fatalf("download headers: %v", export.Header())
	}
	if bytes.Contains(export.Body.Bytes(), []byte(narrative)) || bytes.Contains(export.Body.Bytes(), []byte("narrative")) {
		t.Fatalf("export leaked member-local narrative: %s", export.Body.String())
	}
	restored, downloadedID := decodeExportedClaim(t, export.Body.Bytes())
	if !restored.Verify() || !bytes.Equal(c.CanonicalBytes(), restored.CanonicalBytes()) || restored.ID() != id || downloadedID != idHex {
		t.Fatal("download does not preserve the complete signed claim and its ID")
	}
	if !restored.AssertedAt.Equal(at) {
		t.Fatalf("timestamp lost precision: %s != %s", restored.AssertedAt, at)
	}
	// Every signed component remains authenticated, including the nonce and exact instant.
	mutations := map[string]func(*techtree.Claim){
		"platform": func(c *techtree.Claim) { c.Platform += "-other" },
		"claimant": func(c *techtree.Claim) {
			c.Claimant = append(ed25519.PublicKey(nil), c.Claimant...)
			c.Claimant[0] ^= 1
		},
		"kind":      func(c *techtree.Claim) { c.Kind = techtree.KindTechnique },
		"inputs":    func(c *techtree.Claim) { c.InputsHash[0] ^= 1 },
		"method":    func(c *techtree.Claim) { c.MethodHash[0] ^= 1 },
		"result":    func(c *techtree.Claim) { c.ResultHash[0] ^= 1 },
		"nonce":     func(c *techtree.Claim) { c.Nonce[0] ^= 1 },
		"time":      func(c *techtree.Claim) { c.AssertedAt = c.AssertedAt.Add(time.Nanosecond) },
		"signature": func(c *techtree.Claim) { c.Signature = append([]byte(nil), c.Signature...); c.Signature[0] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := restored
			mutate(&changed)
			if changed.Verify() {
				t.Fatal("tampered export verified")
			}
		})
	}
	after, _ := do(t, h, "GET", "/api/v1/claims/"+idHex, nil)
	if !bytes.Equal(before.Body.Bytes(), after.Body.Bytes()) {
		t.Fatal("export changed the existing summary or stored claim")
	}
}

func TestClaimExportRejectsMalformedOrMissingIDs(t *testing.T) {
	h := newTestServer(t)
	for _, tc := range []struct {
		id     string
		status int
	}{
		{"not-hex", http.StatusBadRequest},
		{strings.Repeat("a", 62), http.StatusBadRequest},
		{strings.Repeat("0", 64), http.StatusNotFound},
	} {
		t.Run(tc.id, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/claims/"+tc.id+"/export", nil))
			if rec.Code != tc.status || rec.Header().Get("Content-Disposition") != "" {
				t.Fatalf("status/headers: %d %v", rec.Code, rec.Header())
			}
		})
	}
}
