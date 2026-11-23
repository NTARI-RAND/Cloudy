package consumerapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func configuredRequestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServerWithLimits(platform, RequestLimits{StructuredBytes: 1024, ClaimBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRequestLimitsConfiguredBoundaries(t *testing.T) {
	for _, path := range jsonWritePaths {
		for _, extra := range []int{-1, 0, 1} {
			for _, declared := range []bool{true, false} {
				checkConfiguredBoundary(t, path, extra, declared)
			}
		}
	}
}

func checkConfiguredBoundary(t *testing.T, path string, extra int, declared bool) {
	t.Helper()
	limit := 1024
	if path == "/api/v1/claims" {
		limit = 2048
	}
	s := configuredRequestServer(t)
	body := append([]byte("{}"), bytes.Repeat([]byte(" "), limit+extra-2)...)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if !declared {
		req.ContentLength = -1
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	want := http.StatusBadRequest
	if extra > 0 {
		want = http.StatusRequestEntityTooLarge
	}
	if rec.Code != want {
		t.Errorf("%s size=%d declared=%v: got %d, want %d", path, len(body), declared, rec.Code, want)
	}
}

func TestRequestLimitsSignedRegistrationBoundary(t *testing.T) {
	for _, extra := range []int{-1, 0, 1} {
		for _, declared := range []bool{true, false} {
			checkSignedRegistrationBoundary(t, extra, declared)
		}
	}
}

func checkSignedRegistrationBoundary(t *testing.T, extra int, declared bool) {
	t.Helper()
	s := configuredRequestServer(t)
	before := ingressState(t, s)
	body := signedRegistration(t, s)
	body = append(body, bytes.Repeat([]byte(" "), 1024+extra-len(body))...)
	req := httptest.NewRequest(http.MethodPost, memberWritePath, bytes.NewReader(body))
	if !declared {
		req.ContentLength = -1
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	want := http.StatusOK
	if extra > 0 {
		want = http.StatusRequestEntityTooLarge
	}
	if rec.Code != want {
		t.Errorf("extra=%d declared=%v got %d, want %d", extra, declared, rec.Code, want)
	}
	if extra > 0 && !reflect.DeepEqual(before, ingressState(t, s)) {
		t.Error("overflow mutated members")
	}
}

func TestRequestLimitsSignedClaimBoundary(t *testing.T) {
	for _, extra := range []int{-1, 0, 1} {
		s, err := NewServerWithLimits(platform, RequestLimits{1024, 2048})
		if err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		pub, priv := key(94)
		registerMember(t, h, pub, priv)
		narrative := "member-local narrative with escaped characters: \n\t and café"
		c, body := signedClaim(t, pub, priv, narrative)
		body = append(body, bytes.Repeat([]byte(" "), 2048+extra-len(body))...)
		before := ingressState(t, s)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claims", bytes.NewReader(body))
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if extra > 0 {
			if rec.Code != http.StatusRequestEntityTooLarge || !reflect.DeepEqual(before, ingressState(t, s)) {
				t.Fatalf("overflow changed state or got %d", rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
		id := c.ID()
		get, view := do(t, h, http.MethodGet, "/api/v1/claims/"+hx(id[:]), nil)
		if get.Code != http.StatusOK {
			t.Fatalf("stored signed claim unreadable: %d", get.Code)
		}
		if view["narrative"].(map[string]any)["inputs"] != narrative {
			t.Error("signed narrative changed")
		}
	}
}
