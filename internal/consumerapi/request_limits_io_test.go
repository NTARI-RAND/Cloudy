package consumerapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type observedRequestBody struct {
	io.Reader
	read     int
	closed   bool
	closeErr error
}

func (b *observedRequestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *observedRequestBody) Close() error { b.closed = true; return b.closeErr }

type failingRequestReader struct{}

func (failingRequestReader) Read([]byte) (int, error) { return 0, errors.New("body unavailable") }

func TestRequestLimitsBoundReadsAndCloseBody(t *testing.T) {
	for _, declared := range []bool{true, false} {
		s, err := NewServerWithLimits(platform, RequestLimits{1024, 2048})
		if err != nil {
			t.Fatal(err)
		}
		body := &observedRequestBody{Reader: io.LimitReader(&endlessSpaces{}, 1<<30)}
		req := httptest.NewRequest(http.MethodPost, memberWritePath, body)
		req.ContentLength = -1
		if declared {
			req.ContentLength = 1 << 30
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("got %d want 413", rec.Code)
		}
		maxRead := 1025
		if declared {
			maxRead = 0
		}
		if body.read > maxRead {
			t.Errorf("consumed %d bytes, maximum %d", body.read, maxRead)
		}
		if !body.closed {
			t.Error("rejected body not closed")
		}
	}
}

type endlessSpaces struct{}

func (*endlessSpaces) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestRequestLimitsReadFailureDoesNotRegister(t *testing.T) {
	s, err := NewServerWithLimits(platform, RequestLimits{1024, 2048})
	if err != nil {
		t.Fatal(err)
	}
	body := &observedRequestBody{Reader: io.MultiReader(bytes.NewReader(signedRegistration(t, s)), failingRequestReader{})}
	req := httptest.NewRequest(http.MethodPost, memberWritePath, body)
	before := ingressState(t, s)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rec.Code)
	}
	if !body.closed {
		t.Error("failed body not closed")
	}
	if !reflect.DeepEqual(before, ingressState(t, s)) {
		t.Error("partial body registered member")
	}
}

func TestRequestLimitsCloseFailureDoesNotRegister(t *testing.T) {
	s, err := NewServerWithLimits(platform, RequestLimits{1024, 2048})
	if err != nil {
		t.Fatal(err)
	}
	body := &observedRequestBody{Reader: bytes.NewReader(signedRegistration(t, s)), closeErr: errors.New("close failed")}
	req := httptest.NewRequest(http.MethodPost, memberWritePath, body)
	before := ingressState(t, s)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("got %d want 400", rec.Code)
	}
	if !reflect.DeepEqual(before, ingressState(t, s)) {
		t.Error("close failure registered member")
	}
}
