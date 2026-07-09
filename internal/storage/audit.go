package storage

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Challenge asks a host to prove possession of one byte range of a sealed
// shard, salted by a nonce so the answer cannot be precomputed or replayed.
// The wire envelope that will carry challenges (and the node signature over
// responses that makes them payable, non-repudiable metering facts) is SCP
// v0.3 scope — see Development/SCP-completion-roadmap.md. This file is the
// member-side substance: what to ask and how to check the answer.
type Challenge struct {
	Offset int64
	Length int64
	Nonce  [16]byte
}

// ChallengeTable is a LABELED STAND-IN proof-of-storage: at seal time the
// member precomputes m single-use challenges per shard and stores the
// expected digests in the manifest (Locker). Each audit spends one entry;
// when a shard's table runs dry the member refreshes it by re-reading the
// shard (which is itself a probe). Homomorphic-tag PoR — unbounded
// challenges without stored expectations — is the named follow-up.
type ChallengeTable struct {
	Challenges []Challenge
	Expected   [][32]byte
	next       int
}

var (
	// ErrTableExhausted means every precomputed challenge was spent.
	ErrTableExhausted = errors.New("storage: challenge table exhausted")
	// ErrBadChallenge means a challenge range does not fit the shard.
	ErrBadChallenge = errors.New("storage: challenge range outside shard")
)

// BuildChallengeTable draws m random challenges over sealed and computes
// their expected digests. Runs on the member's device at seal time, before
// the shard leaves; the table goes in the manifest, never to the host.
func BuildChallengeTable(sealed []byte, m int, entropy io.Reader) (*ChallengeTable, error) {
	if m < 1 {
		return nil, fmt.Errorf("storage: challenge count must be >= 1, got %d", m)
	}
	if len(sealed) == 0 {
		return nil, ErrBadChallenge
	}
	t := &ChallengeTable{
		Challenges: make([]Challenge, m),
		Expected:   make([][32]byte, m),
	}
	for i := 0; i < m; i++ {
		off, err := uniformInt(entropy, len(sealed))
		if err != nil {
			return nil, err
		}
		maxLen := len(sealed) - off
		span, err := uniformInt(entropy, maxLen)
		if err != nil {
			return nil, err
		}
		ch := Challenge{Offset: int64(off), Length: int64(span) + 1}
		if _, err := io.ReadFull(entropy, ch.Nonce[:]); err != nil {
			return nil, fmt.Errorf("storage: reading nonce: %w", err)
		}
		digest, err := Respond(sealed, ch)
		if err != nil {
			return nil, err
		}
		t.Challenges[i] = ch
		t.Expected[i] = digest
	}
	return t, nil
}

// Next returns the next unspent challenge and its expected digest, spending
// it. Single-use is what defeats replay: a host that recorded an old answer
// is never asked the same question again.
func (t *ChallengeTable) Next() (Challenge, [32]byte, error) {
	if t.next >= len(t.Challenges) {
		return Challenge{}, [32]byte{}, ErrTableExhausted
	}
	i := t.next
	t.next++
	return t.Challenges[i], t.Expected[i], nil
}

// Remaining reports how many challenges are left before a refresh is due.
func (t *ChallengeTable) Remaining() int { return len(t.Challenges) - t.next }

// Respond computes the proof digest for a challenge over a sealed shard:
// SHA-256(nonce || offset || length || sealed[offset:offset+length]). Runs
// on the HOST (agent side); binding the parameters into the hash means an
// answer for one range never doubles as an answer for another.
func Respond(sealed []byte, ch Challenge) ([32]byte, error) {
	if ch.Offset < 0 || ch.Length < 1 || ch.Offset+ch.Length > int64(len(sealed)) {
		return [32]byte{}, fmt.Errorf("%w: offset %d length %d over %d bytes",
			ErrBadChallenge, ch.Offset, ch.Length, len(sealed))
	}
	h := sha256.New()
	h.Write(ch.Nonce[:])
	var params [16]byte
	binary.BigEndian.PutUint64(params[:8], uint64(ch.Offset))
	binary.BigEndian.PutUint64(params[8:], uint64(ch.Length))
	h.Write(params[:])
	h.Write(sealed[ch.Offset : ch.Offset+ch.Length])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// VerifyProof compares a host's response against the expected digest in
// constant time. True means the host held those exact sealed bytes after
// the nonce was issued.
func VerifyProof(expected, response [32]byte) bool {
	return subtle.ConstantTimeCompare(expected[:], response[:]) == 1
}
