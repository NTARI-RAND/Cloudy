package economy

// JFA conformance bindings for the economy layer.
//
// Test names carry the Janus registry ID they bind (jfa-conformance-suite.py
// in NTARI-RAND/Janus), so a CI log parser can map a PASS/FAIL back to the
// invariant: TestInvariant_<ID>_<Name>, with any "-" in the ID written "_".

import (
	"errors"
	"math/rand"
	"sync"
	"testing"
)

// TestInvariant_L1_ZeroSumBalance binds registry ID L1: "each exchange moves
// two balances netting to zero."
//
// TestZeroSum already proves the end-state sum on one ledger, driven
// serially. This binding adds what L1 needs beyond that:
//
//  1. Concurrency: several payers post at once, through two Ledgers sharing
//     one Store, so admission races and catch-up are exercised.
//  2. Per-exchange netting: every admitted record in the store moves exactly
//     two accounts, by -amount and +amount — not just a sum that happens to
//     come out zero at the end.
//  3. Determinism: balances are a function of the sealed record, so a fresh
//     Open over the same store reproduces every balance and the zero sum.
func TestInvariant_L1_ZeroSumBalance(t *testing.T) {
	const (
		debitCap      = 300
		spendsPerPeer = 60
	)
	f := newFixture(t, ModeCredit, debitCap, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
	l2, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("second Open over the shared store: %v", err)
	}
	ledgers := []*Ledger{f.ledger, l2}

	// One goroutine per payer, so each payer's nonces stay sequential while
	// different payers race each other across both ledgers.
	var wg sync.WaitGroup
	admitted := make([]int, len(f.members))
	errs := make(chan error, len(f.members))
	for pi := range f.members {
		wg.Add(1)
		go func(pi int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(pi) + 1))
			payer := f.members[pi]
			var nonce uint64
			for i := 0; i < spendsPerPeer; i++ {
				ti := (pi + 1 + rng.Intn(len(f.members)-1)) % len(f.members)
				s := f.spend(payer, f.members[ti], Amount(rng.Intn(120)+1), nonce+1)
				switch err := ledgers[i%2].Post(s); {
				case err == nil:
					nonce++
					admitted[pi]++
				case errors.Is(err, ErrLimit):
					// The uniform cap is the only legitimate refusal here.
				default:
					errs <- err
					return
				}
			}
		}(pi)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("unexpected rejection under concurrency: %v", err)
	}

	total := 0
	for _, n := range admitted {
		total += n
	}
	if total == 0 {
		t.Fatal("no spends admitted; the binding exercised nothing")
	}

	// (2) Every sealed exchange nets to zero on its own.
	recs, err := f.store.All()
	if err != nil {
		t.Fatalf("store.All: %v", err)
	}
	if len(recs) != total {
		t.Fatalf("store holds %d records, want %d admitted spends", len(recs), total)
	}
	fold := map[AccountID]int64{}
	for i, r := range recs {
		s, ok := r.(Spend)
		if !ok {
			t.Fatalf("record %d is %T, want Spend", i, r)
		}
		if s.From == s.To {
			t.Fatalf("record %d moves one account, want two", i)
		}
		before := fold[s.From] + fold[s.To]
		fold[s.From] -= int64(s.Amount)
		fold[s.To] += int64(s.Amount)
		if after := fold[s.From] + fold[s.To]; after != before {
			t.Fatalf("record %d changed the pair's sum by %d, want 0", i, after-before)
		}
	}

	// End state: the sum over all accounts is exactly zero, on both live
	// ledgers (after catch-up) and on a fresh replay.
	reopened, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("reopen for replay: %v", err)
	}
	// The live ledgers may each lag the store (a ledger only catches up when
	// it posts), so they are checked for a zero sum over their own applied
	// prefix; the fresh replay is checked against the full fold.
	var sum int64
	for _, m := range f.members {
		b := int64(reopened.Balance(m.id))
		if b != fold[m.id] {
			t.Fatalf("replayed balance %d != folded balance %d: balances must be a function of the record", b, fold[m.id])
		}
		if b < -debitCap {
			t.Fatalf("balance %d below the uniform cap -%d", b, debitCap)
		}
		sum += b
	}
	if sum != 0 {
		t.Fatalf("sum of balances = %d after %d concurrent spends, want exactly 0", sum, total)
	}
	for li, l := range ledgers {
		var s int64
		for _, m := range f.members {
			s += int64(l.Balance(m.id))
		}
		if s != 0 {
			t.Fatalf("live ledger %d sum = %d, want exactly 0 at every applied prefix", li, s)
		}
	}
}
