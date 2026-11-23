package consumerapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// RequestLimits bounds encoded JSON bytes at this frontend's HTTP ingress.
// These are deployment controls, not limits on signed artifacts in the commons.
type RequestLimits struct {
	StructuredBytes int64
	ClaimBytes      int64
}

// DefaultRequestLimits allows larger claim bodies for member-local narrative.
// Structural requests carry keys, hashes, signatures and short labels instead.
func DefaultRequestLimits() RequestLimits {
	return RequestLimits{StructuredBytes: 64 << 10, ClaimBytes: 1 << 20}
}

// NewServerWithLimits constructs the same member-facing composition as NewServer
// with explicit positive HTTP body limits. It does not alter signed data.
func NewServerWithLimits(platform string, limits RequestLimits) (*Server, error) {
	if limits.StructuredBytes <= 0 || limits.ClaimBytes <= 0 {
		return nil, errors.New("consumerapi: request byte limits must be positive")
	}
	s, err := NewServer(platform)
	if err != nil {
		return nil, err
	}
	s.requestLimits = limits
	return s, nil
}

// limitRequest reads the entire bounded body before a handler can mutate state.
// Merely bounding Decode would miss excess bytes after its first JSON value.
func limitRequest(limit int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readRequestBody(w, r, limit)
		if err != nil {
			var oversized *http.MaxBytesError
			if errors.As(err, &oversized) {
				writeErr(w, http.StatusRequestEntityTooLarge, "request body exceeds configured byte limit")
			} else {
				writeErr(w, http.StatusBadRequest, "invalid JSON body")
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r)
	}
}

// readRequestBody closes the original body before any write handler runs.
func readRequestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	bounded := http.MaxBytesReader(w, r.Body, limit)
	if r.ContentLength > limit {
		return nil, errors.Join(&http.MaxBytesError{Limit: limit}, bounded.Close())
	}
	body, err := io.ReadAll(bounded)
	return body, errors.Join(err, bounded.Close())
}
