package coord

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/opcred"
	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// decodeHeaderForTest mirrors the coordinator's wire decode so the test can
// verify the attached header the way SoHoLINK will.
func decodeHeaderForTest(t *testing.T, raw string) operator.OperatorTransmission {
	t.Helper()
	jb, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("header not base64: %v", err)
	}
	var w struct {
		OperatorID string `json:"operator_id"`
		TsUnixNano int64  `json:"ts_unix_nano"`
		Nonce      string `json:"nonce"`
		Seq        uint64 `json:"seq"`
		Algo       string `json:"algo"`
		Idx0       int    `json:"idx0"`
		Idx1       int    `json:"idx1"`
		Sig0       string `json:"sig0"`
		Sig1       string `json:"sig1"`
	}
	if err := json.Unmarshal(jb, &w); err != nil {
		t.Fatalf("header not JSON: %v", err)
	}
	d := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	return operator.OperatorTransmission{
		OperatorID: w.OperatorID, TsUnixNano: w.TsUnixNano, Nonce: d(w.Nonce),
		Seq: w.Seq, Algo: w.Algo, Idx0: w.Idx0, Idx1: w.Idx1,
		Sig0: d(w.Sig0), Sig1: d(w.Sig1),
	}
}

// A client built with DialAsOperator must carry a valid operator header on its
// /v0 requests, and that header must decode+verify against the keyset — the
// full client-side auth path, from signer to wire, end to end.
func TestDialAsOperator_AttachesVerifiableHeader(t *testing.T) {
	ks, err := opcred.GenerateKeyset()
	if err != nil {
		t.Fatal(err)
	}
	signer := opcred.NewTransmissionSigner("cloudy", ks)

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(opcred.OperatorHeaderName)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"CoordinatorID":"soholink","Terms":{"ContributorShareBps":6500,"PlatformFeeBps":3500}}`))
	}))
	defer srv.Close()

	c := DialAsOperator(srv.URL, func(r *http.Request) error {
		tx, err := signer.Next()
		if err != nil {
			return err
		}
		r.Header.Set(opcred.OperatorHeaderName, opcred.EncodeOperatorHeader(tx))
		return nil
	})

	if _, err := c.Fees(context.Background()); err != nil {
		t.Fatalf("Fees call: %v", err)
	}
	if gotHeader == "" {
		t.Fatal("coordinator received no operator header")
	}
	tx := decodeHeaderForTest(t, gotHeader)
	if err := tx.Verify(ks.KeyMap()); err != nil {
		t.Fatalf("attached header did not verify against the keyset: %v", err)
	}
	if tx.OperatorID != "cloudy" {
		t.Errorf("operator id = %q, want cloudy", tx.OperatorID)
	}
}

// A decoration failure must fail the request closed (never sent unauthenticated).
func TestDialAsOperator_FailClosed(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer srv.Close()

	c := DialAsOperator(srv.URL, func(*http.Request) error { return context.DeadlineExceeded })
	if _, err := c.Fees(context.Background()); err == nil {
		t.Fatal("expected the request to fail when decoration fails")
	}
	if reached {
		t.Fatal("request reached the server despite a decoration failure — not fail-closed")
	}
}
