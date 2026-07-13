package covenant

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// admitted mints an Admitted directly for store-level tests. Only tests may
// do this — outside the package, Book.Record is the sole mint.
func admitted(assessor, subject MemberID, ex ExchangeRef, category string, l Level, sig []byte) Admitted {
	return Admitted{a: Assessment{
		Assessor:  assessor,
		Subject:   subject,
		Exchange:  ex,
		Relation:  RelationTrade,
		Category:  category,
		Level:     l,
		IssuedAt:  time.Unix(1700000000, 0).UTC(),
		Signature: sig,
	}}
}

func TestMemStoreAtomicUniqueness(t *testing.T) {
	alice, _, _ := testMember(1)
	bob, _, _ := testMember(2)
	s := NewMemStore()

	const n = 64
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Append(admitted(alice, bob, ref(0xAA), testCategory, LevelBasicPromise, nil))
		}(i)
	}
	wg.Wait()

	var ok, dup, other int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrDuplicate):
			dup++
		default:
			other++
		}
	}
	if ok != 1 || dup != n-1 || other != 0 {
		t.Errorf("concurrent Appends of one (assessor, exchange, category): %d succeeded, %d ErrDuplicate, %d other; want exactly 1, %d, 0 — uniqueness must be atomic at the persistence boundary", ok, dup, other, n-1)
	}
	got, err := s.BySubject(bob)
	if err != nil {
		t.Fatalf("BySubject = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("store holds %d assessments after the race, want 1", len(got))
	}
}

// TestMemStoreUniquenessIsPerCategory pins the triple key at the persistence
// boundary: the same (assessor, exchange) under a second category is a
// distinct verdict slot, and each slot is single-use.
func TestMemStoreUniquenessIsPerCategory(t *testing.T) {
	alice, _, _ := testMember(1)
	bob, _, _ := testMember(2)
	s := NewMemStore()

	if err := s.Append(admitted(alice, bob, ref(0xAA), "reliability", LevelBasicPromise, nil)); err != nil {
		t.Fatalf("first Append = %v", err)
	}
	// Same pair, different category: admitted.
	if err := s.Append(admitted(alice, bob, ref(0xAA), "support", LevelDelight, nil)); err != nil {
		t.Fatalf("Append under a second category = %v, want nil — uniqueness is (assessor, exchange, category)", err)
	}
	// Duplicate within each category: rejected.
	if err := s.Append(admitted(alice, bob, ref(0xAA), "reliability", LevelDelight, nil)); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate (assessor, exchange, reliability) = %v, want ErrDuplicate", err)
	}
	if err := s.Append(admitted(alice, bob, ref(0xAA), "support", LevelBasicPromise, nil)); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate (assessor, exchange, support) = %v, want ErrDuplicate", err)
	}

	got, err := s.BySubject(bob)
	if err != nil {
		t.Fatalf("BySubject = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("store holds %d assessments, want 2 — one per category slot", len(got))
	}
}

func TestMemStoreAppendOrder(t *testing.T) {
	s := NewMemStore()
	s1, _, _ := testMember(1)
	s2, _, _ := testMember(2)

	// Interleave appends across two subjects; assessors and exchanges differ.
	type step struct {
		assessorSeed byte
		subject      MemberID
		exByte       byte
		level        Level
	}
	steps := []step{
		{0x10, s1, 0x01, LevelBasicPromise},
		{0x20, s2, 0x02, LevelNoTrust},
		{0x30, s1, 0x03, LevelDelight},
		{0x40, s2, 0x04, LevelCynicalSatisfaction},
		{0x50, s1, 0x05, LevelNoNegativeConsequences},
	}
	for _, st := range steps {
		assessor, _, _ := testMember(st.assessorSeed)
		if err := s.Append(admitted(assessor, st.subject, ref(st.exByte), testCategory, st.level, nil)); err != nil {
			t.Fatalf("Append = %v", err)
		}
	}

	got, err := s.BySubject(s1)
	if err != nil {
		t.Fatalf("BySubject = %v", err)
	}
	wantLevels := []Level{LevelBasicPromise, LevelDelight, LevelNoNegativeConsequences}
	if len(got) != len(wantLevels) {
		t.Fatalf("BySubject(s1) returned %d assessments, want %d", len(got), len(wantLevels))
	}
	for i, ad := range got {
		a := ad.Assessment()
		if a.Subject != s1 {
			t.Errorf("entry %d has subject %s, want the queried subject only", i, a.Subject)
		}
		if a.Level != wantLevels[i] {
			t.Errorf("entry %d level = %s, want %s — BySubject must preserve append order", i, a.Level, wantLevels[i])
		}
	}
}

func TestMemStoreDefensiveCopies(t *testing.T) {
	s := NewMemStore()
	alice, _, _ := testMember(1)
	bob, _, _ := testMember(2)
	sig := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := s.Append(admitted(alice, bob, ref(0xAA), testCategory, LevelBasicPromise, append([]byte{}, sig...))); err != nil {
		t.Fatalf("Append = %v", err)
	}

	first, err := s.BySubject(bob)
	if err != nil {
		t.Fatalf("BySubject = %v", err)
	}
	// Mutate everything reachable from the returned value.
	gotSig := first[0].Assessment().Signature
	for i := range gotSig {
		gotSig[i] = 0x00
	}
	first[0] = Admitted{}

	second, err := s.BySubject(bob)
	if err != nil {
		t.Fatalf("BySubject = %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("store lost or gained entries after caller mutation: %d, want 1", len(second))
	}
	a := second[0].Assessment()
	if a.Assessor != alice || a.Subject != bob || a.Category != testCategory || a.Level != LevelBasicPromise {
		t.Errorf("stored assessment changed after caller mutation: %+v", a)
	}
	if !bytes.Equal(a.Signature, sig) {
		t.Errorf("stored signature changed after caller mutation: %x, want %x — BySubject must return defensive copies", a.Signature, sig)
	}
}

func TestMemStoreRejectsZeroAdmitted(t *testing.T) {
	s := NewMemStore()
	if err := s.Append(Admitted{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Append(zero Admitted) = %v, want ErrInvalid — the compile-time Admitted guarantee's residual hole must be closed at runtime", err)
	}
	// Nothing may have been recorded under any subject, including the empty one.
	got, err := s.BySubject("")
	if err != nil {
		t.Fatalf("BySubject = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("zero Admitted reached the store: %d entries", len(got))
	}
}
