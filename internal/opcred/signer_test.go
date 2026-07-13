package opcred

import (
	"bytes"
	"errors"
	"testing"

	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

func TestNextRoundTrip(t *testing.T) {
	ks := mustKeyset(t)
	km := ks.KeyMap()
	s := NewTransmissionSigner("op-live", ks)

	// The protocol's own Verify is the oracle: every successive transmission
	// must pass the exact check the coordinator middleware runs.
	const n = 25
	for i := 0; i < n; i++ {
		tx, err := s.Next()
		if err != nil {
			t.Fatalf("Next() %d: %v", i, err)
		}
		if err := tx.Verify(km); err != nil {
			t.Fatalf("Next() %d does not verify: %v", i, err)
		}
	}
}

func TestPairRotation(t *testing.T) {
	ks := mustKeyset(t)
	s := NewTransmissionSigner("op-rotate", ks)

	// Over one full cycle every unordered distinct pair appears exactly once.
	seen := make(map[[2]int]int)
	for i := 0; i < len(signingPairs); i++ {
		tx, err := s.Next()
		if err != nil {
			t.Fatalf("Next() %d: %v", i, err)
		}
		if tx.Idx0 == tx.Idx1 {
			t.Fatalf("Next() %d: idx0 == idx1 == %d", i, tx.Idx0)
		}
		lo, hi := tx.Idx0, tx.Idx1
		if lo > hi {
			lo, hi = hi, lo
		}
		seen[[2]int{lo, hi}]++
	}
	if len(seen) != 21 {
		t.Fatalf("saw %d distinct pairs over a full cycle, want 21", len(seen))
	}
	for pair, count := range seen {
		if count != 1 {
			t.Errorf("pair %v used %d times in one cycle, want 1", pair, count)
		}
	}
}

func TestSeqAndNonceDiscipline(t *testing.T) {
	ks := mustKeyset(t)
	s := NewTransmissionSigner("op-seq", ks)

	var lastSeq uint64
	nonces := make(map[string]bool)
	for i := 0; i < 30; i++ {
		tx, err := s.Next()
		if err != nil {
			t.Fatalf("Next() %d: %v", i, err)
		}
		if i > 0 && tx.Seq <= lastSeq {
			t.Fatalf("Next() %d: seq %d not strictly greater than %d", i, tx.Seq, lastSeq)
		}
		lastSeq = tx.Seq
		if len(tx.Nonce) < operator.MinNonceLen {
			t.Fatalf("Next() %d: nonce length %d < MinNonceLen", i, len(tx.Nonce))
		}
		key := string(tx.Nonce)
		if nonces[key] {
			t.Fatalf("Next() %d: nonce repeated", i)
		}
		nonces[key] = true
	}
}

func TestTamperedTransmissionsRejected(t *testing.T) {
	ks := mustKeyset(t)
	km := ks.KeyMap()

	tests := []struct {
		name    string
		mutate  func(tx *operator.OperatorTransmission)
		wantErr error
	}{
		{
			name: "flipped signature byte",
			mutate: func(tx *operator.OperatorTransmission) {
				tx.Sig0[0] ^= 0xff
			},
			wantErr: operator.ErrBadSignature,
		},
		{
			name: "same index swapped in post-sign",
			mutate: func(tx *operator.OperatorTransmission) {
				tx.Idx1 = tx.Idx0
			},
			wantErr: operator.ErrSameIndex,
		},
		{
			name: "short nonce injected post-sign",
			mutate: func(tx *operator.OperatorTransmission) {
				tx.Nonce = bytes.Repeat([]byte{1}, operator.MinNonceLen-1)
			},
			wantErr: operator.ErrNonceTooShort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewTransmissionSigner("op-tamper", ks)
			tx, err := s.Next()
			if err != nil {
				t.Fatalf("Next(): %v", err)
			}
			tc.mutate(&tx)
			if err := tx.Verify(km); !errors.Is(err, tc.wantErr) {
				t.Errorf("Verify = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
