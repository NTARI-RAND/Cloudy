package record

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// domainChain tags the one chain derivation in both its arities: the
// single-field seed (LogID over the operator key) and the two-field fold
// step (previous head, leaf). Canon's length prefixes keep the two shapes
// disjoint, and neither is a signature payload.
const domainChain = "drops/chain/v0"

// chainStep folds one leaf hash into the running chain head.
func chainStep(prev, leaf Hash) Hash {
	return Hash(sha256.Sum256(canon.New(domainChain).Bytes(prev[:]).Bytes(leaf[:]).Sum()))
}

// Store is the minimal append-only persistence surface: update and delete
// are absent verbs, not forbidden ones. Log never trusts a Store — chains
// are re-verified on open.
type Store interface {
	// Append persists e as the next entry; it MUST NOT reorder or overwrite.
	Append(e Entry) error
	// At returns the entry at sequence seq or an error when out of range.
	At(seq uint64) (Entry, error)
	// Len returns the number of entries persisted.
	Len() (uint64, error)
}

// MemStore is the in-memory Store; sufficient for tests and single-process
// deployments.
type MemStore struct {
	entries []Entry
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{}
}

// cloneEntry copies e's slice-backed fields so a stored entry can never be
// mutated through a slice the caller still holds.
func cloneEntry(e Entry) Entry {
	e.Proposer = append(ed25519.PublicKey(nil), e.Proposer...)
	e.Acceptor = append(ed25519.PublicKey(nil), e.Acceptor...)
	e.ProposerSeal = append([]byte(nil), e.ProposerSeal...)
	e.AcceptorSeal = append([]byte(nil), e.AcceptorSeal...)
	return e
}

// Append implements Store.
func (s *MemStore) Append(e Entry) error {
	s.entries = append(s.entries, cloneEntry(e))
	return nil
}

// At implements Store.
func (s *MemStore) At(seq uint64) (Entry, error) {
	if seq >= uint64(len(s.entries)) {
		return Entry{}, fmt.Errorf("record: sequence %d out of range (len %d)", seq, len(s.entries))
	}
	return cloneEntry(s.entries[seq]), nil
}

// Len implements Store.
func (s *MemStore) Len() (uint64, error) {
	return uint64(len(s.entries)), nil
}

// Log is ONE operator's record: a LogID-seeded hash chain over dialog-sealed
// entries. No package-level log, no merge, no cross-log query or ordering
// exists anywhere in the surface. The operator's entire power is assigning
// sequence numbers: it holds no key that can produce a member seal, so it
// can order covenants but never author, amend, or remove one.
type Log struct {
	id    Hash
	store Store
	heads []Hash          // heads[i] is the chain head before entry i; heads[len(leaves)] is the current head
	leafs []Hash          // leaf IDs in sequence order
	index map[Hash]uint64 // leaf ID -> sequence, for dedup and Corrects resolution
}

// OpenLog opens the operator's log over s, replaying and cryptographically
// re-verifying every stored entry (seals, log binding, corrections,
// duplicates, chain fold); a store whose contents do not re-verify is
// rejected, so out-of-band tampering cannot be silently resumed. It takes
// only the PUBLIC key: verification-only replicas can open a log, and
// opening one grants no signing power.
func OpenLog(operator ed25519.PublicKey, s Store) (*Log, error) {
	if len(operator) != ed25519.PublicKeySize {
		return nil, errors.New("record: operator key is malformed")
	}
	if s == nil {
		return nil, errors.New("record: nil store")
	}
	id := LogID(operator)
	l := &Log{
		id:    id,
		store: s,
		heads: []Hash{id},
		index: make(map[Hash]uint64),
	}
	n, err := s.Len()
	if err != nil {
		return nil, fmt.Errorf("record: reading store length: %w", err)
	}
	for seq := uint64(0); seq < n; seq++ {
		e, err := s.At(seq)
		if err != nil {
			return nil, fmt.Errorf("record: reading stored entry %d: %w", seq, err)
		}
		leaf, err := l.check(e)
		if err != nil {
			return nil, fmt.Errorf("record: stored entry %d does not re-verify: %w", seq, err)
		}
		l.admit(leaf)
	}
	return l, nil
}

// check applies every admission gate to e against the log's current state
// without mutating anything; it returns e's leaf ID on success.
func (l *Log) check(e Entry) (Hash, error) {
	if !e.Verify() {
		return Hash{}, errors.New("record: entry is not fully dialog-sealed")
	}
	if e.Log != l.id {
		return Hash{}, errors.New("record: entry is bound to a different log")
	}
	if e.Corrects != zeroHash {
		if _, ok := l.index[e.Corrects]; !ok {
			return Hash{}, errors.New("record: correction references no entry in this log")
		}
	}
	leaf := e.ID()
	if _, ok := l.index[leaf]; ok {
		return Hash{}, errors.New("record: entry already appended (duplicate leaf)")
	}
	return leaf, nil
}

// admit folds an already-checked leaf into the in-memory chain state.
func (l *Log) admit(leaf Hash) {
	seq := uint64(len(l.leafs))
	l.index[leaf] = seq
	l.leafs = append(l.leafs, leaf)
	l.heads = append(l.heads, chainStep(l.heads[seq], leaf))
}

// Append admits e only if e.Verify() passes, e.Log equals this log's LogID,
// a nonzero Corrects equals the ID of an entry already in this log, and
// e.ID() is not already present; it persists e and returns its sequence
// number. There is no other mutating method.
func (l *Log) Append(e Entry) (uint64, error) {
	leaf, err := l.check(e)
	if err != nil {
		return 0, err
	}
	if err := l.store.Append(e); err != nil {
		return 0, fmt.Errorf("record: persisting entry: %w", err)
	}
	seq := uint64(len(l.leafs))
	l.admit(leaf)
	return seq, nil
}

// Checkpoint returns the unsigned checkpoint over the current head at UTC
// instant at; the operator seals it with Checkpoint.Sign. Sizes are
// monotonic because the log only appends. The head of an empty log is the
// LogID seed.
func (l *Log) Checkpoint(at time.Time) Checkpoint {
	size := uint64(len(l.leafs))
	return Checkpoint{
		Log:      l.id,
		Size:     size,
		Head:     l.heads[size],
		IssuedAt: at,
	}
}

// Prove returns the inclusion proof for the entry at seq relative to the
// current head; issue the matching Checkpoint in the same quiescent state.
func (l *Log) Prove(seq uint64) (Proof, error) {
	size := uint64(len(l.leafs))
	if seq >= size {
		return Proof{}, fmt.Errorf("record: sequence %d out of range (size %d)", seq, size)
	}
	return Proof{
		Prior: l.heads[seq],
		Links: append([]Hash(nil), l.leafs[seq+1:]...),
	}, nil
}

// LeavesSince returns the leaf hashes of entries at positions
// [size, current size) — the extension evidence a witness or member needs
// for VerifyConsistency.
func (l *Log) LeavesSince(size uint64) ([]Hash, error) {
	current := uint64(len(l.leafs))
	if size > current {
		return nil, fmt.Errorf("record: size %d exceeds log size %d", size, current)
	}
	return append([]Hash(nil), l.leafs[size:]...), nil
}
