package consumerapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/record"
)

func TestConsistencyRequiresWholeUnsignedDecimalSize(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		want  uint64
		valid bool
	}{
		{name: "omitted defaults to zero", valid: true},
		{name: "empty defaults to zero", query: "from=", valid: true},
		{name: "zero", query: "from=0", valid: true},
		{name: "positive", query: "from=12", want: 12, valid: true},
		{name: "leading zero remains decimal", query: "from=012", want: 12, valid: true},
		{name: "maximum uint64", query: "from=18446744073709551615", want: ^uint64(0), valid: true},
		{name: "trailing letters", query: "from=0junk"},
		{name: "fraction", query: "from=1.5"},
		{name: "exponent", query: "from=1e2"},
		{name: "hex prefix", query: "from=0x10"},
		{name: "negative", query: "from=-1"},
		{name: "leading plus", query: "from=" + url.QueryEscape("+1")},
		{name: "leading space", query: "from=" + url.QueryEscape(" 1")},
		{name: "trailing space", query: "from=" + url.QueryEscape("1 ")},
		{name: "newline", query: "from=" + url.QueryEscape("1\n")},
		{name: "overflow", query: "from=18446744073709551616"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/consistency?"+tc.query, nil)
			res := httptest.NewRecorder()
			called := false
			var s Server
			s.serveConsistency(res, req, func(from uint64) ([]record.Hash, uint64, error) {
				called = true
				if from != tc.want {
					t.Errorf("proof requested from %d, want %d", from, tc.want)
				}
				return nil, from, nil
			})
			if !tc.valid {
				if res.Code != http.StatusBadRequest || called {
					t.Fatalf("malformed size: status %d, proof called %t; want 400 before proof generation", res.Code, called)
				}
				return
			}
			if res.Code != http.StatusOK || !called {
				t.Fatalf("valid size: status %d, proof called %t", res.Code, called)
			}
			var body consistencyResponse
			if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.From != tc.want || body.Size != tc.want || body.Proof == nil || len(body.Proof) != 0 {
				t.Fatalf("unexpected proof response: %+v", body)
			}
		})
	}
}

func TestConsistencyRoutesRejectMalformedAndOutOfLogSizes(t *testing.T) {
	h := newTestServer(t)
	for _, path := range []string{"/api/v1/drops/checkpoints/consistency", "/api/v1/lifecycle/checkpoints/consistency"} {
		t.Run(path, func(t *testing.T) {
			for _, query := range []string{"", "?from=", "?from=0"} {
				res, body := do(t, h, http.MethodGet, path+query, nil)
				if res.Code != http.StatusOK || body["from"] != float64(0) || body["size"] != float64(0) {
					t.Fatalf("empty log %s: status %d, body %v", query, res.Code, body)
				}
			}
			for _, query := range []string{"?from=0junk", "?from=1", "?from=18446744073709551615"} {
				res, _ := do(t, h, http.MethodGet, path+query, nil)
				if res.Code != http.StatusBadRequest {
					t.Fatalf("invalid/out-of-log %s: status %d, want 400", query, res.Code)
				}
			}
		})
	}
}
