package opcred

import (
	"sync"

	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// The wire structs below mirror the coordinator's public onboarding
// conformance API with identical JSON tags. Cloudy cannot import the
// coordinator's internal packages, so the shapes are duplicated here; the
// JSON tags are the compatibility contract.
//
// Grading on the coordinator side is against FRESH per-onboarding oracles it
// computes itself, so answers here are always computed from the challenge
// fields through the real protocol canon and signing — never from vectors or
// testdata, which would be replayable.

// ChallengeA is a Suite A (canonical-signing) challenge: fresh
// OperatorTransmission fields, including the two signing indices the
// coordinator dictates. The operator must return the canonical bytes of a
// transmission with exactly these fields, plus a 2-of-7 ConformanceResponse
// signature over those bytes.
type ChallengeA struct {
	ChallengeID string `json:"challenge_id"`
	OperatorID  string `json:"operator_id"`
	TsUnixNano  int64  `json:"ts_unix_nano"`
	Nonce       []byte `json:"nonce"`
	Seq         uint64 `json:"seq"`
	Algo        string `json:"algo"`
	Idx0        int    `json:"idx0"`
	Idx1        int    `json:"idx1"`
}

// ResponseA is the operator's Suite A answer.
type ResponseA struct {
	ChallengeID    string `json:"challenge_id"`
	CanonicalBytes []byte `json:"canonical_bytes"`
	Idx0           int    `json:"idx0"`
	Idx1           int    `json:"idx1"`
	Sig0           []byte `json:"sig0"`
	Sig1           []byte `json:"sig1"`
}

// ChallengeB is a Suite B (transmission) challenge: fresh transmission fields
// without indices. The operator picks its own distinct pair, signs a full
// OperatorTransmission, and returns indices plus signatures; the coordinator
// rebuilds the transmission and runs the real protocol Verify.
type ChallengeB struct {
	ChallengeID string `json:"challenge_id"`
	OperatorID  string `json:"operator_id"`
	TsUnixNano  int64  `json:"ts_unix_nano"`
	Nonce       []byte `json:"nonce"`
	Seq         uint64 `json:"seq"`
	Algo        string `json:"algo"`
}

// ResponseB is the operator's Suite B answer.
type ResponseB struct {
	ChallengeID string `json:"challenge_id"`
	Idx0        int    `json:"idx0"`
	Idx1        int    `json:"idx1"`
	Sig0        []byte `json:"sig0"`
	Sig1        []byte `json:"sig1"`
}

// ConformanceResponder answers onboarding conformance challenges from the
// keyset. Suite C is graded entirely on the coordinator side and needs no
// operator response, so there is no AnswerC.
type ConformanceResponder struct {
	mu         sync.Mutex
	operatorID string
	ks         *Keyset
	pairCursor int
}

// NewConformanceResponder returns a responder over the keyset for operatorID.
func NewConformanceResponder(operatorID string, ks *Keyset) *ConformanceResponder {
	return &ConformanceResponder{operatorID: operatorID, ks: ks}
}

// validateChallengeFields rejects a malformed challenge before any key is
// touched. Errors are the protocol's own, so callers can map them directly.
func validateChallengeFields(nonce []byte, algo string) error {
	if len(nonce) < operator.MinNonceLen {
		return operator.ErrNonceTooShort
	}
	if algo != operator.AlgoEd25519 {
		return operator.ErrUnknownAlgo
	}
	return nil
}

// AnswerA answers a Suite A challenge: it builds an OperatorTransmission with
// EXACTLY the challenge fields (including the challenge-dictated indices),
// takes its CanonicalBytes through the real protocol canon — the byte-equality
// half of the grade — then signs a ConformanceResponse whose Challenge is
// those bytes with the keys at the dictated indices. The ConformanceResponse
// domain tag differs from the transmission tag, so the signatures produced
// here can never replay as a live transmission.
func (c *ConformanceResponder) AnswerA(ch ChallengeA) (ResponseA, error) {
	if err := validateChallengeFields(ch.Nonce, ch.Algo); err != nil {
		return ResponseA{}, err
	}
	if ch.Idx0 < 0 || ch.Idx0 >= operator.KeyIndexCount ||
		ch.Idx1 < 0 || ch.Idx1 >= operator.KeyIndexCount {
		return ResponseA{}, operator.ErrIndexRange
	}
	if ch.Idx0 == ch.Idx1 {
		return ResponseA{}, operator.ErrSameIndex
	}

	tx := operator.OperatorTransmission{
		OperatorID: ch.OperatorID,
		TsUnixNano: ch.TsUnixNano,
		Nonce:      ch.Nonce,
		Seq:        ch.Seq,
		Algo:       ch.Algo,
		Idx0:       ch.Idx0,
		Idx1:       ch.Idx1,
	}
	canonical := tx.CanonicalBytes()

	cr := operator.ConformanceResponse{
		OperatorID: ch.OperatorID,
		Challenge:  canonical,
		Algo:       ch.Algo,
	}
	cr.Sign(c.ks.priv[ch.Idx0], c.ks.priv[ch.Idx1], ch.Idx0, ch.Idx1)

	return ResponseA{
		ChallengeID:    ch.ChallengeID,
		CanonicalBytes: canonical,
		Idx0:           cr.Idx0,
		Idx1:           cr.Idx1,
		Sig0:           cr.Sig0,
		Sig1:           cr.Sig1,
	}, nil
}

// AnswerB answers a Suite B challenge: it builds the full transmission from
// the fresh challenge fields, picks the next distinct pair from an internal
// rotation cursor (so repeated runs vary the pair), signs, and returns the
// indices and signatures. The coordinator rebuilds the transmission and runs
// the real protocol Verify.
func (c *ConformanceResponder) AnswerB(ch ChallengeB) (ResponseB, error) {
	if err := validateChallengeFields(ch.Nonce, ch.Algo); err != nil {
		return ResponseB{}, err
	}

	c.mu.Lock()
	pair := signingPairs[c.pairCursor%len(signingPairs)]
	c.pairCursor++
	c.mu.Unlock()

	tx := operator.OperatorTransmission{
		OperatorID: ch.OperatorID,
		TsUnixNano: ch.TsUnixNano,
		Nonce:      ch.Nonce,
		Seq:        ch.Seq,
		Algo:       ch.Algo,
	}
	tx.Sign(c.ks.priv[pair[0]], c.ks.priv[pair[1]], pair[0], pair[1])

	return ResponseB{
		ChallengeID: ch.ChallengeID,
		Idx0:        tx.Idx0,
		Idx1:        tx.Idx1,
		Sig0:        tx.Sig0,
		Sig1:        tx.Sig1,
	}, nil
}
