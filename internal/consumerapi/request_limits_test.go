package consumerapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/record"
	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

const memberWritePath = "/api/v1/members"

var jsonWritePaths = []string{
	memberWritePath, "/api/v1/claims", "/api/v1/references",
	"/api/v1/market/listings", "/api/v1/drops", "/api/v1/credit/spends",
	"/api/v1/assessments", "/api/v1/assessments/" + strings.Repeat("0", 64) + "/answers",
	"/api/v1/disputes", "/api/v1/disputes/" + strings.Repeat("0", 64) + "/withdraw",
}

// An omitted route guard would return a domain/JSON error instead of 413.
func TestRequestLimitsEveryJSONWrite(t *testing.T) {
	payload := []byte(`{"unused":"` + strings.Repeat("x", 2<<20) + `"}`)
	for _, path := range jsonWritePaths {
		for _, declared := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/declared=%v", path, declared), func(t *testing.T) {
				checkOversizedWrite(t, path, declared, payload)
			})
		}
	}
}

func checkOversizedWrite(t *testing.T, path string, declared bool, payload []byte) {
	t.Helper()
	s, err := NewServer(platform)
	if err != nil {
		t.Fatal(err)
	}
	before := ingressState(t, s)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	if !declared {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized write: got %d, want 413: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json" || !json.Valid(rec.Body.Bytes()) {
		t.Errorf("error is not JSON: %s", rec.Body.String())
	}
	if after := ingressState(t, s); !reflect.DeepEqual(before, after) {
		t.Errorf("rejected request mutated stores: before %v, after %v", before, after)
	}
}

func ingressState(t *testing.T, s *Server) []any {
	t.Helper()
	records, err := s.ecoStore.All()
	if err != nil {
		t.Fatal(err)
	}
	recordCount, err := s.recStore.Len()
	if err != nil {
		t.Fatal(err)
	}
	lifecycleCount, err := s.lifeStore.Len()
	if err != nil {
		t.Fatal(err)
	}
	return []any{len(s.byMember), len(s.byAccount), s.tree.Head(), s.catalog.Head(),
		recordCount, lifecycleCount, len(records), len(s.manifest), len(s.disputesByExchange)}
}

func signedRegistration(t *testing.T, s *Server) []byte {
	t.Helper()
	pub, priv := key(91)
	body, err := json.Marshal(registerRequest{PublicKey: hex.EncodeToString(pub),
		Signature: hex.EncodeToString(ed25519.Sign(priv, s.registerChallenge(pub)))})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Reading only the first JSON value would admit this real signed registration.
func TestRequestLimitsRejectSignedRegistrationWithOversizedSuffix(t *testing.T) {
	for _, declared := range []bool{true, false} {
		s, err := NewServer(platform)
		if err != nil {
			t.Fatal(err)
		}
		before := ingressState(t, s)
		body := append(signedRegistration(t, s), bytes.Repeat([]byte(" "), 2<<20)...)
		req := httptest.NewRequest(http.MethodPost, memberWritePath, bytes.NewReader(body))
		if !declared {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("got %d, want 413", rec.Code)
		}
		if !reflect.DeepEqual(before, ingressState(t, s)) {
			t.Error("oversized registration changed member stores")
		}
	}
}

func signedClaim(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, narrative string) (techtree.Claim, []byte) {
	t.Helper()
	c, err := techtree.NewClaim(platform, pub, techtree.KindFact, techtree.HashNarrative([]byte(narrative)),
		techtree.HashNarrative(nil), techtree.HashNarrative(nil), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claimDTO{Platform: c.Platform, Claimant: hx(c.Claimant), Kind: string(c.Kind),
		InputsHash: hx(c.InputsHash[:]), MethodHash: hx(c.MethodHash[:]), ResultHash: hx(c.ResultHash[:]),
		Nonce: hx(c.Nonce[:]), AssertedAtNs: c.AssertedAt.UnixNano(), Signature: hx(c.Signature), Inputs: narrative})
	if err != nil {
		t.Fatal(err)
	}
	return c, body
}

func TestRequestLimitsRejectSignedClaimBeforeLockerWrite(t *testing.T) {
	s, err := NewServer(platform)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	pub, priv := key(92)
	registerMember(t, h, pub, priv)
	narrative := strings.Repeat("n", 2<<20)
	_, body := signedClaim(t, pub, priv, narrative)
	before := ingressState(t, s)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claims", bytes.NewReader(body))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got %d, want 413: %s", rec.Code, rec.Body.String())
	}
	if !reflect.DeepEqual(before, ingressState(t, s)) {
		t.Error("oversized claim changed stores")
	}
	if _, exists := s.locker.Get(record.HashContent([]byte(narrative))); exists {
		t.Error("rejected narrative entered Locker")
	}
}
