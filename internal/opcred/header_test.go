package opcred

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// decodeOperatorHeader mirrors the coordinator's decoder (SoHoLINK
// internal/api.decodeOperatorHeader) so the test can prove Cloudy's encoding is
// exactly what the coordinator will decode and verify. It is intentionally
// test-only: at runtime Cloudy encodes, never decodes.
func decodeOperatorHeader(t *testing.T, raw string) operator.OperatorTransmission {
	t.Helper()
	jb, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("header not base64: %v", err)
	}
	var w transmissionWire
	if err := json.Unmarshal(jb, &w); err != nil {
		t.Fatalf("header not JSON: %v", err)
	}
	dec := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("byte field not base64: %v", err)
		}
		return b
	}
	return operator.OperatorTransmission{
		OperatorID: w.OperatorID,
		TsUnixNano: w.TsUnixNano,
		Nonce:      dec(w.Nonce),
		Seq:        w.Seq,
		Algo:       w.Algo,
		Idx0:       w.Idx0,
		Idx1:       w.Idx1,
		Sig0:       dec(w.Sig0),
		Sig1:       dec(w.Sig1),
	}
}

// The load-bearing cross-implementation test: a transmission Cloudy signs and
// encodes must decode — via the coordinator's exact wire shape — to a
// transmission the PROTOCOL's own Verify accepts against the keyset. If this
// passes, SoHoLINK's OperatorAuth (same decode + same Verify) accepts it too.
func TestEncodeOperatorHeader_DecodesAndVerifies(t *testing.T) {
	ks, err := GenerateKeyset()
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	signer := NewTransmissionSigner("cloudy", ks)

	tx, err := signer.Next()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	hdr := EncodeOperatorHeader(tx)

	got := decodeOperatorHeader(t, hdr)
	if err := got.Verify(ks.KeyMap()); err != nil {
		t.Fatalf("coordinator-style decode+Verify rejected a Cloudy-encoded header: %v", err)
	}
	if got.OperatorID != "cloudy" || got.Algo != operator.AlgoEd25519 {
		t.Errorf("decoded fields wrong: id=%q algo=%q", got.OperatorID, got.Algo)
	}
	if got.Idx0 == got.Idx1 {
		t.Errorf("signing indices must differ, both %d", got.Idx0)
	}
}

// Field-name contract: the decoded JSON must use the exact snake_case keys the
// coordinator's decoder expects — a rename on either side is a silent auth break.
func TestOperatorHeaderWireFieldNames(t *testing.T) {
	ks, _ := GenerateKeyset()
	tx, _ := NewTransmissionSigner("cloudy", ks).Next()
	jb, _ := base64.StdEncoding.DecodeString(EncodeOperatorHeader(tx))
	var m map[string]any
	if err := json.Unmarshal(jb, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"operator_id", "ts_unix_nano", "nonce", "seq", "algo", "idx0", "idx1", "sig0", "sig1"} {
		if _, ok := m[k]; !ok {
			t.Errorf("header JSON missing required field %q", k)
		}
	}
	if OperatorHeaderName != "X-SohoCloud-Operator" {
		t.Errorf("header name %q must match the coordinator constant", OperatorHeaderName)
	}
}
