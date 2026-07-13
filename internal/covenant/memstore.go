package covenant

import (
	"fmt"
	"sync"
)

// MemStore is the in-memory Store: mutex-guarded, append-only, with atomic
// (Assessor, Exchange, Category) uniqueness. It persists nothing —
// deliberately, no serialized form of the covenant record is defined in this
// package.
type MemStore struct {
	mu        sync.Mutex
	seen      map[string]struct{}     // (assessor, exchange, relation, category) uniqueness keys
	bySubject map[MemberID][]Admitted // append order per subject
	byID      map[[32]byte]Admitted   // Assessment.ID() -> admitted
	answers   map[[32]byte]AdmittedAnswer
}

// NewMemStore returns an empty in-memory Store.
func NewMemStore() *MemStore {
	return &MemStore{
		seen:      make(map[string]struct{}),
		bySubject: make(map[MemberID][]Admitted),
		byID:      make(map[[32]byte]Admitted),
		answers:   make(map[[32]byte]AdmittedAnswer),
	}
}

// Append implements Store: records ad, or returns ErrDuplicate for a repeated
// (Assessor, Exchange, Category) and ErrInvalid for the zero Admitted. The
// uniqueness check and the insert happen under one lock, so uniqueness is
// atomic under concurrent Appends — no time-of-check/time-of-use window.
func (s *MemStore) Append(ad Admitted) error {
	a := ad.Assessment()
	if a.Assessor == "" {
		return fmt.Errorf("%w: zero Admitted", ErrInvalid)
	}
	key := string(a.Assessor) + "\x00" + string(a.Exchange[:]) + "\x00" + string(a.Relation) + "\x00" + a.Category
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.seen[key]; dup {
		return ErrDuplicate
	}
	s.seen[key] = struct{}{}
	s.bySubject[a.Subject] = append(s.bySubject[a.Subject], ad)
	s.byID[a.ID()] = ad
	return nil
}

// ByID implements Store.
func (s *MemStore) ByID(id [32]byte) (Admitted, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ad, ok := s.byID[id]
	return ad, ok, nil
}

// AppendAnswer implements Store: one answer per assessment, forever.
func (s *MemStore) AppendAnswer(aa AdmittedAnswer) error {
	an := aa.Answer()
	if an.Answerer == "" {
		return fmt.Errorf("%w: zero AdmittedAnswer", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.answers[an.Assessment]; dup {
		return ErrDuplicate
	}
	s.answers[an.Assessment] = aa
	return nil
}

// AnswerFor implements Store.
func (s *MemStore) AnswerFor(id [32]byte) (AdmittedAnswer, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aa, ok := s.answers[id]
	return aa, ok, nil
}

// BySubject implements Store: admitted assessments about subject, in append
// order, as defensive copies — the returned slice is fresh, and Admitted
// exposes its assessment only through a copying accessor, so no caller can
// reach the stored bytes.
func (s *MemStore) BySubject(subject MemberID) ([]Admitted, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.bySubject[subject]
	out := make([]Admitted, len(src))
	copy(out, src)
	return out, nil
}
