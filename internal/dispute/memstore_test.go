package dispute

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
)

// mintOpening builds an Admitted opening directly for store-level tests. Only
// tests may do this — outside the package, Registry is the sole mint.
func mintOpening(t *testing.T, cPub ed25519.PublicKey, cKey ed25519.PrivateKey, rPub ed25519.PublicKey, ex ExchangeRef) Admitted {
	t.Helper()
	o := mkOpening(t, cPub, cKey, rPub, ex)
	oc := o.clone()
	id := o.ID()
	return Admitted{dispute: id, id: id, opening: &oc}
}

func TestMemStoreDedupArtifactID(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	s := NewMemStore()
	ad := mintOpening(t, cPub, cKey, rPub, ref(0xA1))
	if err := s.Append(ad); err != nil {
		t.Fatalf("first Append = %v", err)
	}
	// Exact same artifact (same leaf ID) appended again: rejected.
	if err := s.Append(ad); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate artifact ID Append = %v, want ErrDuplicate", err)
	}
}

func TestMemStoreOneLiveCasePerTuple(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	s := NewMemStore()
	ex := ref(0xA1)

	if err := s.Append(mintOpening(t, cPub, cKey, rPub, ex)); err != nil {
		t.Fatalf("first Open Append = %v", err)
	}
	// A different opening artifact (fresh nonce) for the same tuple: rejected
	// while the first case is live.
	if err := s.Append(mintOpening(t, cPub, cKey, rPub, ex)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second live tuple Append = %v, want ErrDuplicate", err)
	}
}

func TestMemStoreTerminalReleasesTuple(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	s := NewMemStore()
	ex := ref(0xA1)

	first := mintOpening(t, cPub, cKey, rPub, ex)
	if err := s.Append(first); err != nil {
		t.Fatalf("Open Append = %v", err)
	}
	// Withdraw the case (terminal), which must release the tuple.
	w := Withdrawal{Platform: "cloudy", Dispute: first.dispute, WithdrawnAt: time.Unix(1, 0).UTC()}
	w.Sign(cKey)
	wc := w.clone()
	if err := s.Append(Admitted{dispute: first.dispute, id: w.leafID(), withdrawal: &wc}); err != nil {
		t.Fatalf("Withdrawal Append = %v", err)
	}
	// A fresh opening for the same tuple is now admissible again.
	if err := s.Append(mintOpening(t, cPub, cKey, rPub, ex)); err != nil {
		t.Fatalf("re-open after terminal = %v, want admission", err)
	}
}

func TestMemStoreRejectsZeroAdmitted(t *testing.T) {
	s := NewMemStore()
	if err := s.Append(Admitted{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Append(zero Admitted) = %v, want ErrInvalid", err)
	}
}

func TestMemStoreByDisputeOrderAndCopies(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	s := NewMemStore()
	ex := ref(0xA1)
	op := mintOpening(t, cPub, cKey, rPub, ex)
	if err := s.Append(op); err != nil {
		t.Fatalf("Append opening = %v", err)
	}
	w := Withdrawal{Platform: "cloudy", Dispute: op.dispute, WithdrawnAt: time.Unix(1, 0).UTC()}
	w.Sign(cKey)
	wc := w.clone()
	if err := s.Append(Admitted{dispute: op.dispute, id: w.leafID(), withdrawal: &wc}); err != nil {
		t.Fatalf("Append withdrawal = %v", err)
	}

	got, err := s.ByDispute(op.dispute)
	if err != nil {
		t.Fatalf("ByDispute = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ByDispute returned %d artifacts, want 2", len(got))
	}
	if _, ok := got[0].Opening(); !ok {
		t.Fatal("first artifact must be the opening (append order)")
	}
	if _, ok := got[1].Withdrawal(); !ok {
		t.Fatal("second artifact must be the withdrawal (append order)")
	}
	// Mutating the returned slice must not affect the store.
	got[0] = Admitted{}
	again, err := s.ByDispute(op.dispute)
	if err != nil {
		t.Fatalf("ByDispute = %v", err)
	}
	if len(again) != 2 {
		t.Fatalf("store lost entries after caller mutation: %d, want 2", len(again))
	}
	if _, ok := again[0].Opening(); !ok {
		t.Fatal("store's first artifact changed after caller mutated the returned slice")
	}

	// An unknown case yields an empty slice, not an error.
	empty, err := s.ByDispute(DisputeID{9: 9})
	if err != nil {
		t.Fatalf("ByDispute(unknown) = %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("unknown case returned %d artifacts, want 0", len(empty))
	}
}

func TestMemStoreAtomicOneLiveCase(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	ex := ref(0xA1)
	s := NewMemStore()

	// Concurrent Appends of DISTINCT opening artifacts for the same tuple:
	// exactly one may win the live slot; the rest are ErrDuplicate.
	const n = 32
	ads := make([]Admitted, n)
	for i := range ads {
		ads[i] = mintOpening(t, cPub, cKey, rPub, ex)
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Append(ads[i])
		}(i)
	}
	wg.Wait()

	ok, dup, other := 0, 0, 0
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
		t.Fatalf("concurrent Opens for one tuple: %d ok, %d dup, %d other; want 1, %d, 0", ok, dup, other, n-1)
	}
}
