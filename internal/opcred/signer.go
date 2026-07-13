package opcred

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// transmissionNonceLen is the fresh CSPRNG nonce length per transmission:
// twice the protocol's MinNonceLen, matching the coordinator's own choice for
// conformance nonces.
const transmissionNonceLen = 2 * operator.MinNonceLen

// signingPairs is the fixed cycle of all unordered distinct index pairs
// (i < j) out of the seven key indices — 21 pairs. Walking this cycle spreads
// signing evenly across all seven keys, which both exercises rotation and
// feeds the coordinator's per-key usage accounting evenly.
var signingPairs = buildSigningPairs()

func buildSigningPairs() [][2]int {
	var pairs [][2]int
	for i := 0; i < operator.KeyIndexCount; i++ {
		for j := i + 1; j < operator.KeyIndexCount; j++ {
			pairs = append(pairs, [2]int{i, j})
		}
	}
	return pairs
}

// TransmissionSigner produces signed OperatorTransmissions for live
// coordinator traffic. It rotates through all 21 distinct key pairs, issues a
// fresh CSPRNG nonce per transmission, and keeps Seq strictly increasing.
//
// Seq is initialized to the construction-time UnixNano so it stays monotone
// across process restarts WITHOUT disk state: the coordinator's replay window
// is scoped per (operator, coordinator) and only requires that Seq advance.
// If durable persistence is later wanted, the seam is this one field.
//
// TransmissionSigner produces the protocol struct only; transport encoding
// (the operator header) is the coordination client's job, not this package's.
type TransmissionSigner struct {
	mu         sync.Mutex
	operatorID string
	ks         *Keyset
	pairCursor int
	seq        uint64
	now        func() time.Time
	rand       io.Reader
}

// NewTransmissionSigner returns a signer over the keyset for operatorID.
func NewTransmissionSigner(operatorID string, ks *Keyset) *TransmissionSigner {
	s := &TransmissionSigner{
		operatorID: operatorID,
		ks:         ks,
		now:        time.Now,
		rand:       rand.Reader,
	}
	s.seq = uint64(s.now().UnixNano())
	return s
}

// Next returns the next signed transmission: fresh nonce, strictly increased
// Seq, current timestamp, and the next key pair in the rotation cycle.
func (s *TransmissionSigner) Next() (operator.OperatorTransmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pair := signingPairs[s.pairCursor%len(signingPairs)]
	s.pairCursor++

	nonce := make([]byte, transmissionNonceLen)
	if _, err := io.ReadFull(s.rand, nonce); err != nil {
		return operator.OperatorTransmission{}, fmt.Errorf("opcred: read nonce: %w", err)
	}

	s.seq++
	tx := operator.OperatorTransmission{
		OperatorID: s.operatorID,
		TsUnixNano: s.now().UnixNano(),
		Nonce:      nonce,
		Seq:        s.seq,
		Algo:       operator.AlgoEd25519,
	}
	tx.Sign(s.ks.priv[pair[0]], s.ks.priv[pair[1]], pair[0], pair[1])
	return tx, nil
}
