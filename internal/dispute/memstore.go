package dispute

import (
	"fmt"
	"sync"
)

// MemStore is the in-memory Store: mutex-guarded, append-only, with atomic
// artifact-ID uniqueness and atomic one-live-case-per-(exchange, complainant,
// respondent) enforcement. It persists nothing — deliberately, no serialized
// form of the dispute record is defined in this package (mirrors covenant and
// economy).
type MemStore struct {
	mu           sync.Mutex
	ids          map[DisputeID]struct{}   // every admitted artifact leaf ID, for dedup
	byDispute    map[DisputeID][]Admitted // append order per case
	openTuple    map[string]DisputeID     // (exchange, complainant, respondent) key -> the case currently open for it
	disputeTuple map[DisputeID]string     // case -> its tuple key, so a terminal artifact can release it
	adjudicated  map[string]struct{}      // tuples permanently settled by a ruling; never re-openable (double-refund guard)
}

// NewMemStore returns an empty in-memory Store.
func NewMemStore() *MemStore {
	return &MemStore{
		ids:          make(map[DisputeID]struct{}),
		byDispute:    make(map[DisputeID][]Admitted),
		openTuple:    make(map[string]DisputeID),
		disputeTuple: make(map[DisputeID]string),
		adjudicated:  make(map[string]struct{}),
	}
}

// Append implements Store. The dedup check, the one-live-case check, the
// already-adjudicated check, and the insert all happen under one lock, so the
// uniqueness guarantees are atomic under concurrent Appends — no
// time-of-check/time-of-use window. An opening registers its tuple as live; a
// WITHDRAWAL releases the tuple (a genuine re-dispute after withdrawal is
// admissible again); a RULING releases the live tuple AND permanently marks it
// adjudicated, so a resolved (exchange, complainant, respondent) can never be
// re-opened — the guard against a second ruling, and thus a double
// refund/escalation, over one exchange.
func (s *MemStore) Append(a Admitted) error {
	if a.dispute == (DisputeID{}) || (a.opening == nil && a.ruling == nil && a.withdrawal == nil) {
		return fmt.Errorf("%w: zero Admitted", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.ids[a.id]; dup {
		return ErrDuplicate
	}
	if key, ok := a.opensCase(); ok {
		if _, done := s.adjudicated[key]; done {
			return ErrAdjudicated
		}
		if _, live := s.openTuple[key]; live {
			return ErrDuplicate
		}
		s.openTuple[key] = a.dispute
		s.disputeTuple[a.dispute] = key
	} else if key, ok := s.disputeTuple[a.dispute]; ok {
		// A terminal artifact releases its case's live tuple. A ruling
		// additionally settles the tuple for good (no re-dispute ever); a
		// withdrawal leaves it re-openable.
		delete(s.openTuple, key)
		if a.ruling != nil {
			s.adjudicated[key] = struct{}{}
		}
	}
	s.ids[a.id] = struct{}{}
	s.byDispute[a.dispute] = append(s.byDispute[a.dispute], a)
	return nil
}

// ByDispute implements Store: admitted artifacts for a case, in append order,
// as a fresh slice. The Admitted values expose their artifacts only through
// copying accessors, so no caller can reach the stored bytes.
func (s *MemStore) ByDispute(id DisputeID) ([]Admitted, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.byDispute[id]
	out := make([]Admitted, len(src))
	copy(out, src)
	return out, nil
}
