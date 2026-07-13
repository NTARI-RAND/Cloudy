package economy

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"
)

const testPlatform = "cloudy-test"

// member is a test participant with a platform-scoped account.
type member struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   AccountID
}

func newTestMember(platform string, seed byte) member {
	priv, pub := seedKey(seed)
	return member{priv: priv, pub: pub, id: AccountIDFor(platform, pub)}
}

// mapDirectory is the out-of-band key registry the tests play the
// composition root with.
type mapDirectory map[AccountID]ed25519.PublicKey

func (d mapDirectory) PublicKey(a AccountID) (ed25519.PublicKey, bool) {
	k, ok := d[a]
	return k, ok
}

// fixture wires a ledger with three seeded stewards (threshold 2) and the
// requested members.
type fixture struct {
	genesis  Genesis
	dir      mapDirectory
	store    *MemStore
	ledger   *Ledger
	stewards []ed25519.PrivateKey
	members  []member
}

func newFixture(t *testing.T, mode Mode, debitCap Amount, memberSeeds ...byte) *fixture {
	t.Helper()
	f := &fixture{dir: mapDirectory{}, store: NewMemStore()}
	var stewardPubs []ed25519.PublicKey
	for _, seed := range []byte{0xA0, 0xA1, 0xA2} {
		priv, pub := seedKey(seed)
		f.stewards = append(f.stewards, priv)
		stewardPubs = append(stewardPubs, pub)
	}
	f.genesis = Genesis{
		Platform:  testPlatform,
		Stewards:  stewardPubs,
		Threshold: 2,
		Policy:    Policy{Mode: mode, DebitCap: debitCap},
	}
	for _, seed := range memberSeeds {
		m := newTestMember(testPlatform, seed)
		f.members = append(f.members, m)
		f.dir[m.id] = m.pub
	}
	l, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("Open of fresh fixture failed: %v", err)
	}
	f.ledger = l
	return f
}

// spend builds and payer-signs a spend on the fixture's platform.
func (f *fixture) spend(from, to member, amt Amount, nonce uint64) Spend {
	s := Spend{
		Platform:     f.genesis.Platform,
		From:         from.id,
		To:           to.id,
		Amount:       amt,
		ExchangeHash: [32]byte{0x5A},
		IssuedAt:     time.Unix(1700000000, 0).UTC(),
		Nonce:        nonce,
	}
	s.Sign(from.priv)
	return s
}

// change builds a PolicyChange signed by the first nSigs stewards.
func (f *fixture) change(pol Policy, version uint64, nSigs int) PolicyChange {
	c := PolicyChange{
		Platform: f.genesis.Platform,
		Policy:   pol,
		Version:  version,
		At:       time.Unix(1700000100, 0).UTC(),
	}
	for i := 0; i < nSigs; i++ {
		c.Sign(f.stewards[i])
	}
	return c
}

func (f *fixture) storeLen(t *testing.T) int {
	t.Helper()
	recs, err := f.store.All()
	if err != nil {
		t.Fatalf("store.All failed: %v", err)
	}
	return len(recs)
}

func TestPostRejectedInEscrowMode(t *testing.T) {
	f := newFixture(t, ModeEscrow, 100, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	s := f.spend(a, b, 10, 1)
	if err := f.ledger.Post(s); !errors.Is(err, ErrCreditDisabled) {
		t.Fatalf("Post in ModeEscrow = %v, want ErrCreditDisabled", err)
	}
	if n := f.storeLen(t); n != 0 {
		t.Fatalf("ModeEscrow appended %d records; this package must record nothing in escrow mode", n)
	}
	if f.ledger.Balance(a.id) != 0 || f.ledger.Balance(b.id) != 0 {
		t.Fatal("rejected spend moved credit")
	}
}

func TestModeSwitchIsOneRecord(t *testing.T) {
	f := newFixture(t, ModeEscrow, 100, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	// Signed once, before the flip; never re-signed.
	s := f.spend(a, b, 10, 1)
	if err := f.ledger.Post(s); !errors.Is(err, ErrCreditDisabled) {
		t.Fatalf("pre-flip Post = %v, want ErrCreditDisabled", err)
	}

	// The flip is exactly one quorum-signed record.
	if err := f.ledger.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 100}, 1, 2)); err != nil {
		t.Fatalf("Enact of mode flip failed: %v", err)
	}
	if n := f.storeLen(t); n != 1 {
		t.Fatalf("mode switch wrote %d records, want exactly 1", n)
	}
	before, _ := f.store.All()
	beforeBytes := make([][]byte, len(before))
	for i, r := range before {
		beforeBytes[i] = r.CanonicalBytes()
	}

	// The byte-identical spend is now admitted unchanged.
	if err := f.ledger.Post(s); err != nil {
		t.Fatalf("post-flip Post of the identical spend failed: %v", err)
	}
	if f.ledger.Balance(a.id) != -10 || f.ledger.Balance(b.id) != 10 {
		t.Fatal("balances wrong after admitted spend")
	}

	// Previously stored records are untouched byte-for-byte.
	after, _ := f.store.All()
	for i, want := range beforeBytes {
		if !bytes.Equal(after[i].CanonicalBytes(), want) {
			t.Fatalf("record %d was rewritten across the mode switch", i)
		}
	}

	// Reopening the same store reproduces identical policy and balances.
	l2, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	if got := l2.Policy(); got != (Policy{Mode: ModeCredit, DebitCap: 100}) {
		t.Fatalf("reopened policy = %+v", got)
	}
	if l2.Balance(a.id) != -10 || l2.Balance(b.id) != 10 {
		t.Fatal("reopened balances differ")
	}
}

func TestZeroSum(t *testing.T) {
	f := newFixture(t, ModeCredit, 500, 0x01, 0x02, 0x03, 0x04)
	rng := rand.New(rand.NewSource(1))
	nonces := map[AccountID]uint64{}

	admitted := 0
	for i := 0; i < 200; i++ {
		fi := rng.Intn(len(f.members))
		ti := (fi + 1 + rng.Intn(len(f.members)-1)) % len(f.members)
		from, to := f.members[fi], f.members[ti]
		amt := Amount(rng.Intn(200) + 1)
		s := f.spend(from, to, amt, nonces[from.id]+1)
		switch err := f.ledger.Post(s); {
		case err == nil:
			nonces[from.id]++
			admitted++
		case errors.Is(err, ErrLimit):
			// Cap refusal is the only legitimate rejection here.
		default:
			t.Fatalf("unexpected rejection: %v", err)
		}
	}
	if admitted == 0 {
		t.Fatal("no spends admitted; test exercised nothing")
	}

	var sum int64
	for _, m := range f.members {
		sum += int64(f.ledger.Balance(m.id))
	}
	if sum != 0 {
		t.Fatalf("sum of balances = %d after %d admitted spends, want exactly 0", sum, admitted)
	}
}

func TestDebitCap(t *testing.T) {
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02, 0x03)
	a, b, operator := f.members[0], f.members[1], f.members[2]

	steps := []struct {
		name    string
		s       Spend
		wantErr error
	}{
		{"to exactly -cap admitted", f.spend(a, b, 100, 1), nil},
		{"one unit past cap refused", f.spend(a, b, 1, 2), ErrLimit},
		{"incoming credit restores headroom", f.spend(b, a, 50, 1), nil},
		{"headroom is spendable back to -cap", f.spend(a, b, 50, 2), nil},
		{"past cap again refused", f.spend(a, b, 1, 3), ErrLimit},
		{"operator key gets the same cap", f.spend(operator, b, 100, 1), nil},
		{"operator cannot go deeper", f.spend(operator, b, 1, 2), ErrLimit},
	}
	for _, tc := range steps {
		err := f.ledger.Post(tc.s)
		if tc.wantErr == nil && err != nil {
			t.Fatalf("%s: Post = %v, want admit", tc.name, err)
		}
		if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Fatalf("%s: Post = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
	if got := f.ledger.Balance(a.id); got != -100 {
		t.Fatalf("payer balance = %d, want -100 (exactly at the uniform cap)", got)
	}
	if got := f.ledger.Balance(operator.id); got != -100 {
		t.Fatalf("operator balance = %d, want -100: the cap must be uniform", got)
	}
}

func TestNonceReplayRejected(t *testing.T) {
	f := newFixture(t, ModeCredit, 1000, 0x01, 0x02, 0x03)
	a, b, c := f.members[0], f.members[1], f.members[2]

	first := f.spend(a, b, 10, 1)
	if err := f.ledger.Post(first); err != nil {
		t.Fatalf("initial spend failed: %v", err)
	}
	if err := f.ledger.Post(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("replaying the identical spend = %v, want ErrReplay", err)
	}
	if err := f.ledger.Post(f.spend(a, b, 5, 1)); !errors.Is(err, ErrReplay) {
		t.Fatalf("equal nonce = %v, want ErrReplay", err)
	}
	if err := f.ledger.Post(f.spend(a, b, 5, 0)); !errors.Is(err, ErrReplay) {
		t.Fatalf("lower nonce = %v, want ErrReplay", err)
	}
	// Nonces are per account, not global: c's nonce 1 is fresh.
	if err := f.ledger.Post(f.spend(c, b, 5, 1)); err != nil {
		t.Fatalf("independent account's nonce 1 rejected: %v", err)
	}
	if n := f.storeLen(t); n != 2 {
		t.Fatalf("store holds %d records, want 2", n)
	}
}

func TestCrossPlatformRejected(t *testing.T) {
	f := newFixture(t, ModeCredit, 1000, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	// Correctly signed — for a different platform's ledger.
	foreign := Spend{
		Platform:     "cloudy-elsewhere",
		From:         a.id,
		To:           b.id,
		Amount:       10,
		ExchangeHash: [32]byte{0x5A},
		IssuedAt:     time.Unix(1700000000, 0).UTC(),
		Nonce:        1,
	}
	foreign.Sign(a.priv)
	if !foreign.Verify(a.pub) {
		t.Fatal("foreign spend should verify on its own platform's bytes")
	}

	err := f.ledger.Post(foreign)
	if err == nil {
		t.Fatal("foreign-platform spend was admitted")
	}
	if n := f.storeLen(t); n != 0 {
		t.Fatalf("rejected foreign spend appended %d records", n)
	}

	// The signature cannot be transplanted onto the local platform: Platform
	// is inside the canonical bytes.
	transplanted := foreign
	transplanted.Platform = f.genesis.Platform
	if transplanted.Verify(a.pub) {
		t.Fatal("foreign signature verified over the local platform's canonical bytes; platform is not bound into the payload")
	}
}

func TestDirectoryCrossCheck(t *testing.T) {
	f := newFixture(t, ModeCredit, 1000, 0x01, 0x02)
	a, b := f.members[0], f.members[1]
	unknown := newTestMember(testPlatform, 0x09) // never registered

	// A lying directory substitutes b's key for a's account.
	f.dir[a.id] = b.pub
	if err := f.ledger.Post(f.spend(a, b, 10, 1)); err == nil {
		t.Fatal("lying directory was not detected by the AccountIDFor cross-check")
	}
	f.dir[a.id] = a.pub

	if err := f.ledger.Post(f.spend(unknown, b, 10, 1)); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("unresolvable payer = %v, want ErrUnknownAccount", err)
	}
	if err := f.ledger.Post(f.spend(a, unknown, 10, 1)); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("unresolvable payee = %v, want ErrUnknownAccount", err)
	}
	if n := f.storeLen(t); n != 0 {
		t.Fatalf("rejected spends appended %d records", n)
	}
}

func TestRejectsBadSpend(t *testing.T) {
	f := newFixture(t, ModeCredit, 1000, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	tests := []struct {
		name    string
		build   func() Spend
		wantErr error // nil means any descriptive rejection
	}{
		{"zero amount", func() Spend { return f.spend(a, b, 0, 1) }, nil},
		{"amount above int64 range", func() Spend {
			return f.spend(a, b, Amount(math.MaxInt64)+1, 1)
		}, nil},
		{"self transfer", func() Spend { return f.spend(a, a, 10, 1) }, nil},
		{"missing signature", func() Spend {
			s := f.spend(a, b, 10, 1)
			s.Signature = nil
			return s
		}, ErrSignature},
		{"wrong-length signature", func() Spend {
			s := f.spend(a, b, 10, 1)
			s.Signature = s.Signature[:len(s.Signature)-1]
			return s
		}, ErrSignature},
		{"corrupted signature", func() Spend {
			s := f.spend(a, b, 10, 1)
			s.Signature[0] ^= 0x01
			return s
		}, ErrSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := f.ledger.Post(tc.build())
			if err == nil {
				t.Fatal("bad spend admitted")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Post = %v, want %v", err, tc.wantErr)
			}
			if n := f.storeLen(t); n != 0 {
				t.Fatalf("rejected spend appended %d records", n)
			}
		})
	}
}

func TestOpenReplaysHistory(t *testing.T) {
	f := newFixture(t, ModeEscrow, 100, 0x01, 0x02, 0x03)
	a, b, c := f.members[0], f.members[1], f.members[2]

	must := func(err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	must(f.ledger.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 100}, 1, 2)), "mode flip")
	must(f.ledger.Post(f.spend(a, b, 60, 1)), "spend 1")
	must(f.ledger.Post(f.spend(b, c, 30, 1)), "spend 2")
	must(f.ledger.Post(f.spend(c, a, 10, 1)), "spend 3")
	must(f.ledger.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 200}, 2, 2)), "cap change")
	must(f.ledger.Post(f.spend(a, b, 100, 2)), "spend under new cap")

	l2, err := Open(f.genesis, f.dir, f.store)
	must(err, "reopen")

	for _, m := range f.members {
		if l2.Balance(m.id) != f.ledger.Balance(m.id) {
			t.Fatalf("replayed balance for member differs: %d != %d", l2.Balance(m.id), f.ledger.Balance(m.id))
		}
	}
	if got := l2.Policy(); got != (Policy{Mode: ModeCredit, DebitCap: 200}) {
		t.Fatalf("replayed policy = %+v", got)
	}
	// Nonces were rebuilt: a's used nonce is refused, the next admits.
	if err := l2.Post(f.spend(a, b, 1, 2)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed nonce state lost: %v", err)
	}
	must(l2.Post(f.spend(a, b, 1, 3)), "next nonce on reopened ledger")
	// Version was rebuilt: v2 is refused, v3 admits.
	if err := l2.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 200}, 2, 2)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed version state lost: %v", err)
	}
	must(l2.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 300}, 3, 2)), "next version on reopened ledger")
}

// smuggledRecord satisfies the Record union from outside the intended set by
// embedding a Spend; Open's exact-type replay switch must reject it even when
// the embedded spend would be admissible on its own.
type smuggledRecord struct{ Spend }

func TestOpenDetectsTamper(t *testing.T) {
	tests := []struct {
		name  string
		build func(f *fixture) // appends directly to f.store, bypassing the ledger
		mode  Mode
	}{
		{
			name: "mutated amount breaks the payer signature",
			mode: ModeCredit,
			build: func(f *fixture) {
				s := f.spend(f.members[0], f.members[1], 10, 1)
				s.Amount = 20 // rewrite after signing
				f.store.Append(0, s)
			},
		},
		{
			name: "spend bypass-written during escrow mode",
			mode: ModeEscrow,
			build: func(f *fixture) {
				f.store.Append(0, f.spend(f.members[0], f.members[1], 10, 1))
			},
		},
		{
			name: "sub-quorum policy change",
			mode: ModeEscrow,
			build: func(f *fixture) {
				f.store.Append(0, f.change(Policy{Mode: ModeCredit, DebitCap: 100}, 1, 1))
			},
		},
		{
			name: "non-monotonic nonce",
			mode: ModeCredit,
			build: func(f *fixture) {
				f.store.Append(0, f.spend(f.members[0], f.members[1], 10, 1))
				f.store.Append(1, f.spend(f.members[0], f.members[1], 5, 1))
			},
		},
		{
			name: "non-monotonic policy version",
			mode: ModeCredit,
			build: func(f *fixture) {
				f.store.Append(0, f.change(Policy{Mode: ModeCredit, DebitCap: 100}, 1, 2))
				f.store.Append(1, f.change(Policy{Mode: ModeCredit, DebitCap: 200}, 1, 2))
			},
		},
		{
			name: "wrong-platform record",
			mode: ModeCredit,
			build: func(f *fixture) {
				a, b := f.members[0], f.members[1]
				s := Spend{
					Platform: "cloudy-elsewhere",
					From:     a.id, To: b.id,
					Amount:   10,
					IssuedAt: time.Unix(1700000000, 0).UTC(),
					Nonce:    1,
				}
				s.Sign(a.priv)
				f.store.Append(0, s)
			},
		},
		{
			name: "smuggled record kind embedding a valid spend",
			mode: ModeCredit,
			build: func(f *fixture) {
				f.store.Append(0, smuggledRecord{f.spend(f.members[0], f.members[1], 10, 1)})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.mode, 100, 0x01, 0x02)
			tc.build(f)
			_, err := Open(f.genesis, f.dir, f.store)
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("Open = %v, want an error wrapping ErrTampered", err)
			}
		})
	}
}

func TestEnactNonRetroactive(t *testing.T) {
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	if err := f.ledger.Post(f.spend(a, b, 100, 1)); err != nil {
		t.Fatalf("spend to the cap failed: %v", err)
	}
	if err := f.ledger.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 50}, 1, 2)); err != nil {
		t.Fatalf("cap reduction failed: %v", err)
	}

	// Honest history reopens cleanly: the old spend is checked against the
	// policy in force at its position, never the current one.
	l2, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("reopen after cap reduction corrupted honest history: %v", err)
	}
	if got := l2.Balance(a.id); got != -100 {
		t.Fatalf("reopened balance = %d, want -100 unchanged", got)
	}
	// But the reduced cap governs the member's NEXT spend.
	if err := f.ledger.Post(f.spend(a, b, 1, 2)); !errors.Is(err, ErrLimit) {
		t.Fatalf("post-reduction spend = %v, want ErrLimit", err)
	}
}

func TestMemStoreAppendOnly(t *testing.T) {
	f := newFixture(t, ModeCredit, 1000, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	store := NewMemStore()
	recs := []Record{
		f.spend(a, b, 1, 1),
		f.change(Policy{Mode: ModeCredit, DebitCap: 5}, 1, 2),
		f.spend(a, b, 2, 2),
	}
	for i, r := range recs {
		if err := store.Append(i, r); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}
	got, err := store.All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	if len(got) != len(recs) {
		t.Fatalf("All returned %d records, want %d", len(got), len(recs))
	}
	for i := range recs {
		if !reflect.DeepEqual(got[i], recs[i]) {
			t.Fatalf("record %d out of append order or altered", i)
		}
	}

	// Append is conditional: a stale position is refused with ErrConflict and
	// appends nothing.
	for _, stale := range []int{0, 2, 4} {
		if err := store.Append(stale, f.spend(a, b, 9, 9)); !errors.Is(err, ErrConflict) {
			t.Fatalf("Append at stale position %d = %v, want ErrConflict", stale, err)
		}
	}
	if cur, _ := store.All(); len(cur) != len(recs) {
		t.Fatalf("conflicting append still stored a record: %d, want %d", len(cur), len(recs))
	}

	// All returns a copy: mutating it must not rewrite history.
	got[0] = got[2]
	again, _ := store.All()
	for i := range recs {
		if !reflect.DeepEqual(again[i], recs[i]) {
			t.Fatalf("mutating All's result altered stored record %d", i)
		}
	}

	// Deep mutation IN: the store must not alias the caller's signature
	// memory, so flipping a byte after Append cannot rewrite history.
	inSpend := f.spend(a, b, 3, 3)
	wantSig := append([]byte(nil), inSpend.Signature...)
	if err := store.Append(3, inSpend); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	inSpend.Signature[0] ^= 0x01
	inChange := f.change(Policy{Mode: ModeCredit, DebitCap: 7}, 2, 2)
	wantSteward := append([]byte(nil), inChange.Sigs[0]...)
	if err := store.Append(4, inChange); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	inChange.Sigs[0][0] ^= 0x01
	deep, _ := store.All()
	if gotSig := deep[3].(Spend).Signature; !bytes.Equal(gotSig, wantSig) {
		t.Fatal("mutating the caller's Spend.Signature after Append rewrote stored history")
	}
	if gotSteward := deep[4].(PolicyChange).Sigs[0]; !bytes.Equal(gotSteward, wantSteward) {
		t.Fatal("mutating the caller's PolicyChange.Sigs after Append rewrote stored history")
	}

	// Deep mutation OUT: All's result must not alias stored memory either.
	deep[3].(Spend).Signature[0] ^= 0x01
	deep[4].(PolicyChange).Sigs[0][0] ^= 0x01
	fresh, _ := store.All()
	if !bytes.Equal(fresh[3].(Spend).Signature, wantSig) {
		t.Fatal("mutating a signature returned by All rewrote stored history")
	}
	if !bytes.Equal(fresh[4].(PolicyChange).Sigs[0], wantSteward) {
		t.Fatal("mutating steward sigs returned by All rewrote stored history")
	}

	// Concurrent Append and Post do not race (meaningful under -race); raw
	// appenders retry on ErrConflict like any store writer must.
	var wg sync.WaitGroup
	raw := NewMemStore()
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				r := Spend{Platform: testPlatform, Nonce: uint64(i)}
				for {
					cur, err := raw.All()
					if err != nil {
						t.Errorf("concurrent All failed: %v", err)
						return
					}
					err = raw.Append(len(cur), r)
					if err == nil {
						break
					}
					if !errors.Is(err, ErrConflict) {
						t.Errorf("concurrent Append failed: %v", err)
						return
					}
				}
			}
		}()
	}
	members := f.members
	for g := 0; g < 2; g++ {
		payer, payee := members[g], members[(g+1)%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := uint64(1); n <= 25; n++ {
				if err := f.ledger.Post(f.spend(payer, payee, 1, n)); err != nil {
					t.Errorf("concurrent Post failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			f.ledger.Balance(members[0].id)
			f.ledger.Policy()
			raw.All()
		}
	}()
	wg.Wait()

	all, _ := raw.All()
	if len(all) != 100 {
		t.Fatalf("concurrent appends stored %d records, want 100", len(all))
	}
	if sum := int64(f.ledger.Balance(members[0].id)) + int64(f.ledger.Balance(members[1].id)); sum != 0 {
		t.Fatalf("sum after concurrent posts = %d, want 0", sum)
	}
}

// TestDirectoryKeyLengthGuard: a caller-supplied Directory can return a key
// of any length, and ed25519.Verify panics on non-canonical lengths; the
// ledger must reject such keys with ErrSignature — on the payer path, the
// payee path, and Open's replay — never crash.
func TestDirectoryKeyLengthGuard(t *testing.T) {
	f := newFixture(t, ModeCredit, 1000, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	// A 16-byte "key" whose AccountID legitimately hashes from those 16
	// bytes, so the AccountIDFor cross-check alone cannot catch it.
	short := bytes.Repeat([]byte{0x42}, 16)
	shortID := AccountIDFor(testPlatform, short)
	f.dir[shortID] = short

	// Payer path: a full-length signature ensures Verify would reach
	// ed25519.Verify — and panic — without the length guard.
	payerSpend := Spend{
		Platform:     testPlatform,
		From:         shortID,
		To:           b.id,
		Amount:       5,
		ExchangeHash: [32]byte{0x5A},
		IssuedAt:     time.Unix(1700000000, 0).UTC(),
		Nonce:        1,
	}
	payerSpend.Signature = bytes.Repeat([]byte{0x01}, ed25519.SignatureSize)
	if err := f.ledger.Post(payerSpend); !errors.Is(err, ErrSignature) {
		t.Fatalf("Post with short payer key = %v, want ErrSignature", err)
	}

	// Payee path: a validly signed spend to the short-keyed account must be
	// rejected, not admitted.
	payeeSpend := Spend{
		Platform:     testPlatform,
		From:         a.id,
		To:           shortID,
		Amount:       5,
		ExchangeHash: [32]byte{0x5A},
		IssuedAt:     time.Unix(1700000000, 0).UTC(),
		Nonce:        1,
	}
	payeeSpend.Sign(a.priv)
	if err := f.ledger.Post(payeeSpend); !errors.Is(err, ErrSignature) {
		t.Fatalf("Post with short payee key = %v, want ErrSignature", err)
	}
	if n := f.storeLen(t); n != 0 {
		t.Fatalf("rejected spends appended %d records", n)
	}

	// Open replay path: a bypass-written spend from the short-keyed account
	// must fail replay with ErrTampered, not panic.
	if err := f.store.Append(0, payerSpend); err != nil {
		t.Fatalf("bypass append failed: %v", err)
	}
	if _, err := Open(f.genesis, f.dir, f.store); !errors.Is(err, ErrTampered) {
		t.Fatalf("Open over short-key spend = %v, want an error wrapping ErrTampered", err)
	}
}

// TestTwoLedgersOneStore: two live ledgers over one store must serialize
// through the conditional append. Before the fix, both cached state
// independently, a reused nonce double-appended, and every later Open failed
// ErrTampered forever.
func TestTwoLedgersOneStore(t *testing.T) {
	f := newFixture(t, ModeCredit, 1000, 0x01, 0x02)
	a, b := f.members[0], f.members[1]
	l2, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("second Open over the same store failed: %v", err)
	}

	if err := f.ledger.Post(f.spend(a, b, 10, 1)); err != nil {
		t.Fatalf("first ledger's spend failed: %v", err)
	}
	// Same payer, same nonce, different bytes, through the second ledger:
	// it must catch up and refuse with ErrReplay, not double-append.
	if err := l2.Post(f.spend(a, b, 25, 1)); !errors.Is(err, ErrReplay) {
		t.Fatalf("reused nonce via second ledger = %v, want ErrReplay", err)
	}
	if n := f.storeLen(t); n != 1 {
		t.Fatalf("store holds %d records after the losing post, want 1", n)
	}
	// The store must remain openable — the old bug bricked it forever.
	if _, err := Open(f.genesis, f.dir, f.store); err != nil {
		t.Fatalf("store no longer opens after the nonce race: %v", err)
	}

	// Catch-up rebuilt the second ledger's derived state, and both ledgers
	// keep interleaving fresh nonces.
	if got := l2.Balance(a.id); got != -10 {
		t.Fatalf("second ledger balance after catch-up = %d, want -10", got)
	}
	if err := l2.Post(f.spend(a, b, 5, 2)); err != nil {
		t.Fatalf("fresh nonce via second ledger failed: %v", err)
	}
	if err := f.ledger.Post(f.spend(a, b, 5, 3)); err != nil {
		t.Fatalf("first ledger failed to catch up past the second's spend: %v", err)
	}

	// Enact takes the same path: a version enacted through one ledger is
	// ErrReplay through the other, never a fork.
	if err := f.ledger.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 2000}, 1, 2)); err != nil {
		t.Fatalf("first ledger's enact failed: %v", err)
	}
	if err := l2.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 3000}, 1, 2)); !errors.Is(err, ErrReplay) {
		t.Fatalf("reused version via second ledger = %v, want ErrReplay", err)
	}
	if err := l2.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 3000}, 2, 2)); err != nil {
		t.Fatalf("next version via second ledger failed: %v", err)
	}

	l3, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("final reopen failed: %v", err)
	}
	if got := l3.Policy(); got != (Policy{Mode: ModeCredit, DebitCap: 3000}) {
		t.Fatalf("replayed policy = %+v", got)
	}
	if got := l3.Balance(a.id); got != -20 {
		t.Fatalf("replayed balance = %d, want -20", got)
	}
}

// TestCallerMutationAfterPost: the store must not alias caller memory, so
// mutating a signature after a successful Post or Enact cannot corrupt
// stored history. Before the fix, Open reported ErrTampered with no
// store-level tampering at all.
func TestCallerMutationAfterPost(t *testing.T) {
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02)
	a, b := f.members[0], f.members[1]

	s := f.spend(a, b, 10, 1)
	if err := f.ledger.Post(s); err != nil {
		t.Fatalf("Post failed: %v", err)
	}
	s.Signature[0] ^= 0x01 // caller scribbles on its own copy after Post

	c := f.change(Policy{Mode: ModeCredit, DebitCap: 200}, 1, 2)
	if err := f.ledger.Enact(c); err != nil {
		t.Fatalf("Enact failed: %v", err)
	}
	c.Sigs[0][0] ^= 0x01 // and after Enact

	if _, err := Open(f.genesis, f.dir, f.store); err != nil {
		t.Fatalf("caller mutation after Post/Enact corrupted stored history: %v", err)
	}
}
