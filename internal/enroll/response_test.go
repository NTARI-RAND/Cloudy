package enroll

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTruncatedResponseFails(t *testing.T) {
	for _, decode := range []bool{false, true} {
		t.Run(map[bool]string{false: "discard", true: "decode"}[decode], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100")
				_, _ = io.WriteString(w, `{}`)
			}))
			defer server.Close()
			var result any
			var target any
			if decode {
				target = &result
			}
			err := NewClient(server.URL).do(context.Background(), http.MethodGet, "/response", nil, target)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated response error = %v, want unexpected EOF", err)
			}
		})
	}
}
