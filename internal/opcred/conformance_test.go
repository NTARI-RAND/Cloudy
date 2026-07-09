package opcred

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// freshChallengeNonce returns a 32-byte CSPRNG nonce, matching the
// coordinator's conformance nonce length.
func freshChallengeNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func freshChallengeA(t *testing.T, operatorID string) ChallengeA {
	t.Helper()
	return ChallengeA{
		ChallengeID: "ch-a-1",
		OperatorID:  operatorID,
		TsUnixNano:  time.Now().UnixNano(),
		Nonce:       freshChallengeNonce(t),
		Seq:         1001,
		Algo:        operator.AlgoEd25519,
		Idx0:        0,
		Idx1:        1,
	}
}

func freshChallengeB(t *testing.T, operatorID string) ChallengeB {
	t.Helper()
	return ChallengeB{
		ChallengeID: "ch-b-1",
		OperatorID:  operatorID,
		TsUnixNano:  time.Now().UnixNano(),
		Nonce:       freshChallengeNonce(t),
		Seq:         2002,
		Algo:        operator.AlgoEd25519,
	}
}

func TestAnswerAMatchesGraderOracle(t *testing.T) {
	const opID = "op-conf-a"
	ks := mustKeyset(t)
	km := ks.KeyMap()
	c := NewConformanceResponder(opID, ks)

	ch := freshChallengeA(t, opID)
	resp, err := c.AnswerA(ch)
	if err != nil {
		t.Fatalf("AnswerA: %v", err)
	}

	// Check 1 (byte-equality): compute the oracle locally exactly as the
	// grader does — the protocol transmission with the challenge fields.
	oracle := operator.OperatorTransmission{
		OperatorID: ch.OperatorID,
		TsUnixNano: ch.TsUnixNano,
		Nonce:      ch.Nonce,
		Seq:        ch.Seq,
		Algo:       ch.Algo,
		Idx0:       ch.Idx0,
		Idx1:       ch.Idx1,
	}.CanonicalBytes()
	if !bytes.Equal(oracle, resp.CanonicalBytes) {
		t.Fatal("response canonical bytes differ from the grader oracle")
	}

	// Check 2 (real signature verify): the grader rebuilds a
	// ConformanceResponse over the fresh bytes and runs the protocol Verify.
	cr := operator.ConformanceResponse{
		OperatorID: opID,
		Challenge:  resp.CanonicalBytes,
		Algo:       operator.AlgoEd25519,
		Idx0:       resp.Idx0,
		Idx1:       resp.Idx1,
		Sig0:       resp.Sig0,
		Sig1:       resp.Sig1,
	}
	if err := cr.Verify(km); err != nil {
		t.Fatalf("ConformanceResponse.Verify: %v", err)
	}
	if resp.ChallengeID != ch.ChallengeID {
		t.Errorf("ChallengeID = %q, want %q", resp.ChallengeID, ch.ChallengeID)
	}
}

func TestAnswerBPassesRealVerify(t *testing.T) {
	const opID = "op-conf-b"
	ks := mustKeyset(t)
	km := ks.KeyMap()
	c := NewConformanceResponder(opID, ks)

	ch := freshChallengeB(t, opID)
	resp, err := c.AnswerB(ch)
	if err != nil {
		t.Fatalf("AnswerB: %v", err)
	}

	// The grader rebuilds the transmission from the stored challenge fields
	// plus the returned indices/signatures and runs the real protocol Verify.
	tx := operator.OperatorTransmission{
		OperatorID: opID,
		TsUnixNano: ch.TsUnixNano,
		Nonce:      ch.Nonce,
		Seq:        ch.Seq,
		Algo:       ch.Algo,
		Idx0:       resp.Idx0,
		Idx1:       resp.Idx1,
		Sig0:       resp.Sig0,
		Sig1:       resp.Sig1,
	}
	if err := tx.Verify(km); err != nil {
		t.Fatalf("rebuilt transmission does not verify: %v", err)
	}
	if resp.Idx0 == resp.Idx1 {
		t.Error("AnswerB used the same index twice")
	}
}

func TestConformanceSignaturesDoNotReplayAsTransmission(t *testing.T) {
	// Domain separation, proven from the client side: the signatures AnswerA
	// produced (conformance domain) must NOT verify as an OperatorTransmission
	// (transmission domain) over the same fields.
	const opID = "op-conf-sep"
	ks := mustKeyset(t)
	km := ks.KeyMap()
	c := NewConformanceResponder(opID, ks)

	ch := freshChallengeA(t, opID)
	resp, err := c.AnswerA(ch)
	if err != nil {
		t.Fatalf("AnswerA: %v", err)
	}

	replay := operator.OperatorTransmission{
		OperatorID: ch.OperatorID,
		TsUnixNano: ch.TsUnixNano,
		Nonce:      ch.Nonce,
		Seq:        ch.Seq,
		Algo:       ch.Algo,
		Idx0:       resp.Idx0,
		Idx1:       resp.Idx1,
		Sig0:       resp.Sig0,
		Sig1:       resp.Sig1,
	}
	if err := replay.Verify(km); err == nil {
		t.Fatal("conformance signatures replayed as a live transmission")
	}
}

func TestBadChallengesRejected(t *testing.T) {
	const opID = "op-conf-bad"
	ks := mustKeyset(t)
	c := NewConformanceResponder(opID, ks)

	tests := []struct {
		name string
		call func(t *testing.T) error
	}{
		{
			name: "suite A index out of range",
			call: func(t *testing.T) error {
				ch := freshChallengeA(t, opID)
				ch.Idx1 = operator.KeyIndexCount
				resp, err := c.AnswerA(ch)
				if err == nil && len(resp.Sig0) > 0 {
					t.Error("signature produced for a bad challenge")
				}
				return err
			},
		},
		{
			name: "suite A negative index",
			call: func(t *testing.T) error {
				ch := freshChallengeA(t, opID)
				ch.Idx0 = -1
				_, err := c.AnswerA(ch)
				return err
			},
		},
		{
			name: "suite A equal indices",
			call: func(t *testing.T) error {
				ch := freshChallengeA(t, opID)
				ch.Idx1 = ch.Idx0
				_, err := c.AnswerA(ch)
				return err
			},
		},
		{
			name: "suite A short nonce",
			call: func(t *testing.T) error {
				ch := freshChallengeA(t, opID)
				ch.Nonce = ch.Nonce[:operator.MinNonceLen-1]
				_, err := c.AnswerA(ch)
				return err
			},
		},
		{
			name: "suite A unknown algo",
			call: func(t *testing.T) error {
				ch := freshChallengeA(t, opID)
				ch.Algo = "not-a-real-algo"
				_, err := c.AnswerA(ch)
				return err
			},
		},
		{
			name: "suite B short nonce",
			call: func(t *testing.T) error {
				ch := freshChallengeB(t, opID)
				ch.Nonce = ch.Nonce[:operator.MinNonceLen-1]
				resp, err := c.AnswerB(ch)
				if err == nil && len(resp.Sig0) > 0 {
					t.Error("signature produced for a bad challenge")
				}
				return err
			},
		},
		{
			name: "suite B unknown algo",
			call: func(t *testing.T) error {
				ch := freshChallengeB(t, opID)
				ch.Algo = "not-a-real-algo"
				_, err := c.AnswerB(ch)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(t); err == nil {
				t.Error("bad challenge accepted, want error")
			}
		})
	}
}
