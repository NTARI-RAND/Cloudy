package opcred

import (
	"encoding/base64"
	"encoding/json"

	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// OperatorHeaderName is the HTTP header that carries an operator transmission on
// the coordinator's node-side /v0 seam. It MUST equal the coordinator's own
// constant (SoHoLINK internal/api.OperatorHeader = "X-SohoCloud-Operator"); the
// name and the value encoding below are the cross-implementation contract, held
// by the round-trip test against the protocol's own Verify.
const OperatorHeaderName = "X-SohoCloud-Operator"

// transmissionWire is the JSON shape base64-encoded into the header value. It
// maps 1:1 onto operator.OperatorTransmission and MUST match the coordinator's
// decoder (SoHoLINK internal/api.operatorTransmissionWire): the snake_case
// field names and the standard-base64 encoding of the byte fields are load
// bearing. The protocol package does not define this transport shape (its
// canon is the SIGNED bytes, not the wire envelope), so the two ends agree on
// it here and by test, not by a shared type — a candidate to hoist into
// sohocloud-protocol later.
type transmissionWire struct {
	OperatorID string `json:"operator_id"`
	TsUnixNano int64  `json:"ts_unix_nano"`
	Nonce      string `json:"nonce"` // base64 std
	Seq        uint64 `json:"seq"`
	Algo       string `json:"algo"`
	Idx0       int    `json:"idx0"`
	Idx1       int    `json:"idx1"`
	Sig0       string `json:"sig0"` // base64 std
	Sig1       string `json:"sig1"` // base64 std
}

// EncodeOperatorHeader serializes a signed transmission to the base64 header
// value the coordinator expects — the client counterpart to the coordinator's
// decodeOperatorHeader. Cloudy only ever encodes (it authenticates AS the
// operator); the coordinator decodes and verifies.
func EncodeOperatorHeader(tx operator.OperatorTransmission) string {
	w := transmissionWire{
		OperatorID: tx.OperatorID,
		TsUnixNano: tx.TsUnixNano,
		Nonce:      base64.StdEncoding.EncodeToString(tx.Nonce),
		Seq:        tx.Seq,
		Algo:       tx.Algo,
		Idx0:       tx.Idx0,
		Idx1:       tx.Idx1,
		Sig0:       base64.StdEncoding.EncodeToString(tx.Sig0),
		Sig1:       base64.StdEncoding.EncodeToString(tx.Sig1),
	}
	b, _ := json.Marshal(w) //nolint:errcheck // transmissionWire has no unmarshalable fields
	return base64.StdEncoding.EncodeToString(b)
}
