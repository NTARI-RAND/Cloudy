package consumerapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestLimitsRealHTTP(t *testing.T) {
	for _, extra := range []int{0, 1} {
		for _, chunked := range []bool{false, true} {
			checkRealRequestBoundary(t, extra, chunked)
		}
	}
}

func checkRealRequestBoundary(t *testing.T, extra int, chunked bool) {
	t.Helper()
	s := configuredRequestServer(t)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	body := signedRegistration(t, s)
	body = append(body, bytes.Repeat([]byte(" "), 1024+extra-len(body))...)
	req, err := http.NewRequest(http.MethodPost, server.URL+memberWritePath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if chunked {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	}
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	want := http.StatusOK
	if extra > 0 {
		want = http.StatusRequestEntityTooLarge
	}
	if response.StatusCode != want || !json.Valid(data) {
		t.Errorf("extra=%d chunked=%v: status=%d body=%s", extra, chunked, response.StatusCode, data)
	}
}

func TestRequestLimitsInvalidConfiguration(t *testing.T) {
	for _, limits := range []RequestLimits{{0, 1024}, {1024, 0}, {-1, 1024}, {1024, -1}} {
		if _, err := NewServerWithLimits(platform, limits); err == nil {
			t.Errorf("accepted invalid limits %+v", limits)
		}
	}
	if _, err := NewServerWithLimits("", RequestLimits{1024, 2048}); err == nil {
		t.Error("accepted empty platform")
	}
}
