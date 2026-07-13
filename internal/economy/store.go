package economy

import (
	"errors"
	"fmt"
	"sync"
)

// ErrConflict is the Store contract's sentinel: Append must return an error
// wrapping it — and append nothing — when the store's current record count
// does not equal the caller's expected position. Ledgers consume it
// internally (they catch up and retry), so callers of Post and Enact never
// see it; it is exported for Store implementers.
var ErrConflict = errors.New("economy: store record count does not match expected append position")

// Store is the append-only persistence surface: records are added, never
// updated, never deleted; corrections are new records. The interface
// structurally has no update or delete, so an erasing store is not
// expressible against it.
//
// Implementation contract (WHY: several Ledgers may share one store, and
// history must stay a single verifiable line, never a fork):
//
//   - Append is CONDITIONAL: it must atomically compare the store's current
//     record count against after and reject with an error wrapping
//     ErrConflict, appending nothing, unless they are equal. This is what
//     makes a nonce spent through one ledger ErrReplay through every other
//     instead of a double-append that bricks Open forever.
//   - Implementations must be linearizable: all Append and All calls observe
//     one total order of appends, so a successful Append(n, r) means r is
//     the (n+1)th record for every observer.
//   - Implementations must not alias caller memory: mutable slice fields
//     (Spend.Signature, PolicyChange.Sigs) must be deep-copied on the way in
//     (Append) and on the way out (All), so no caller mutation before or
//     after the call can rewrite stored history.
type Store interface {
	// Append durably appends one admitted record iff the store currently
	// holds exactly after records; otherwise it returns an error wrapping
	// ErrConflict and appends nothing.
	Append(after int, r Record) error
	// All returns every appended record in append order; the returned slice
	// and every mutable field inside it are the caller's to mutate freely.
	All() ([]Record, error)
}

// MemStore is an in-memory Store and the only Store implementation in v0; the
// durable-format decision is deliberately deferred, so no Marshal, Export, or
// Snapshot exists. The zero value is usable, but NewMemStore is the
// documented construction path. Safe for concurrent use.
type MemStore struct {
	mu      sync.Mutex
	records []Record
}

// NewMemStore returns an empty in-memory store ready for use.
func NewMemStore() *MemStore {
	return &MemStore{}
}

// Append implements Store: the compare against after and the append happen
// under one lock, so appends are linearizable, and the stored record is
// deep-copied so it shares no memory with the caller.
func (m *MemStore) Append(after int, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.records) != after {
		return fmt.Errorf("economy: append expected %d existing records, store holds %d: %w", after, len(m.records), ErrConflict)
	}
	m.records = append(m.records, cloneRecord(r))
	return nil
}

// All implements Store; it returns a deep copy in append order, so mutating
// the returned slice — or any signature bytes inside it — cannot rewrite
// history.
func (m *MemStore) All() ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.records))
	for i, r := range m.records {
		out[i] = cloneRecord(r)
	}
	return out, nil
}

// cloneRecord returns r with every mutable slice field deep-copied. WHY:
// Record kinds are value types, but Spend.Signature and PolicyChange.Sigs are
// slices whose backing arrays would otherwise stay shared with the caller —
// an aliasing store lets s.Signature[0] ^= 1 after a successful Post rewrite
// stored history, which a later Open then misreports as store tampering.
func cloneRecord(r Record) Record {
	switch rec := r.(type) {
	case Spend:
		rec.Signature = cloneBytes(rec.Signature)
		return rec
	case PolicyChange:
		if rec.Sigs != nil {
			sigs := make([][]byte, len(rec.Sigs))
			for i, sig := range rec.Sigs {
				sigs[i] = cloneBytes(sig)
			}
			rec.Sigs = sigs
		}
		return rec
	default:
		// A foreign kind is stored as handed over; it can never replay into
		// a ledger (Open's exact-type switch rejects it with ErrTampered).
		return r
	}
}

// cloneBytes copies b, preserving nil-ness.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
