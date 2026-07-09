package record

import (
	"bytes"
	"testing"
)

// contentN returns a distinct content hash per index.
func contentN(n byte) Hash {
	return HashContent([]byte{'c', n})
}

// buildLog appends n plain sealed entries between a and b to a fresh
// MemStore-backed log for op, returning the log, its store, and the entries.
func buildLog(t *testing.T, op, a, b party, n int) (*Log, *MemStore, []Entry) {
	t.Helper()
	ms := NewMemStore()
	l, err := OpenLog(op.pub, ms)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	id := LogID(op.pub)
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		e := sealedEntry(t, id, a, b, contentN(byte(i)), Hash{}, testInstant)
		seq, err := l.Append(e)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if seq != uint64(i) {
			t.Fatalf("Append %d returned seq %d", i, seq)
		}
		entries = append(entries, e)
	}
	return l, ms, entries
}

func TestAppendGates(t *testing.T) {
	op, other := newParty(t), newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)

	l, _, entries := buildLog(t, op, a, b, 1)

	unsealed, err := NewEntry(id, a.pub, b.pub, contentN(9), Hash{}, testInstant)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	halfP := unsealed
	if err := halfP.Seal(a.priv); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	halfA := unsealed
	if err := halfA.Seal(b.priv); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	foreign := sealedEntry(t, LogID(other.pub), a, b, contentN(9), Hash{}, testInstant)
	dangling := sealedEntry(t, id, a, b, contentN(9), Hash{0xDE, 0xAD}, testInstant)

	rejected := []struct {
		name string
		e    Entry
	}{
		{"unsealed", unsealed},
		{"proposer-sealed only", halfP},
		{"acceptor-sealed only", halfA},
		{"bound to a different operator's log", foreign},
		{"dangling Corrects", dangling},
		{"duplicate leaf", entries[0]},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := l.Append(tc.e); err == nil {
				t.Fatalf("Append must reject %s entry", tc.name)
			}
		})
	}

	// A correction referencing an in-log entry's ID is accepted, and the
	// corrected entry remains readable at its sequence.
	correction := sealedEntry(t, id, a, b, contentN(10), entries[0].ID(), testInstant)
	seq, err := l.Append(correction)
	if err != nil {
		t.Fatalf("Append(correction): %v", err)
	}
	if seq != 1 {
		t.Fatalf("correction seq = %d, want 1", seq)
	}
	got, err := l.store.At(0)
	if err != nil {
		t.Fatalf("At(0): %v", err)
	}
	if got.ID() != entries[0].ID() {
		t.Fatal("corrected entry must remain readable at its original sequence")
	}
}

func TestAppendSequencesAndMemStore(t *testing.T) {
	op, a, b := newParty(t), newParty(t), newParty(t)
	_, ms, entries := buildLog(t, op, a, b, 4)

	n, err := ms.Len()
	if err != nil {
		t.Fatalf("Len: %v", err)
	}
	if n != 4 {
		t.Fatalf("Len = %d, want 4", n)
	}
	for i, want := range entries {
		got, err := ms.At(uint64(i))
		if err != nil {
			t.Fatalf("At(%d): %v", i, err)
		}
		if !bytes.Equal(got.CanonicalBytes(), want.CanonicalBytes()) ||
			!bytes.Equal(got.ProposerSeal, want.ProposerSeal) ||
			!bytes.Equal(got.AcceptorSeal, want.AcceptorSeal) {
			t.Fatalf("At(%d) is not byte-identical to the appended entry", i)
		}
	}
	if _, err := ms.At(4); err == nil {
		t.Fatal("At out of range must error")
	}
}

func TestMemStoreContract(t *testing.T) {
	op, a, b := newParty(t), newParty(t), newParty(t)
	id := LogID(op.pub)
	ms := NewMemStore()
	for i := 0; i < 3; i++ {
		before, err := ms.Len()
		if err != nil {
			t.Fatalf("Len: %v", err)
		}
		e := sealedEntry(t, id, a, b, contentN(byte(i)), Hash{}, testInstant)
		if err := ms.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
		after, err := ms.Len()
		if err != nil {
			t.Fatalf("Len: %v", err)
		}
		if after != before+1 {
			t.Fatalf("Len grew from %d to %d, want +1", before, after)
		}
		got, err := ms.At(before)
		if err != nil {
			t.Fatalf("At(%d): %v", before, err)
		}
		if !bytes.Equal(got.CanonicalBytes(), e.CanonicalBytes()) ||
			!bytes.Equal(got.ProposerSeal, e.ProposerSeal) ||
			!bytes.Equal(got.AcceptorSeal, e.AcceptorSeal) {
			t.Fatal("stored entry must round-trip byte-identically")
		}
	}
}

func TestOpenLogReplayDistrust(t *testing.T) {
	op, other := newParty(t), newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)

	// Honest reopen reproduces the same head.
	l, ms, _ := buildLog(t, op, a, b, 3)
	cpA := l.Checkpoint(testInstant)
	re, err := OpenLog(op.pub, ms)
	if err != nil {
		t.Fatalf("reopening an honest store: %v", err)
	}
	cpB := re.Checkpoint(testInstant)
	if cpA.Head != cpB.Head || cpA.Size != cpB.Size {
		t.Fatal("reopening an honest store must reproduce the same head and size")
	}

	t.Run("mutated field", func(t *testing.T) {
		_, ms, _ := buildLog(t, op, a, b, 3)
		ms.entries[1].Content[0] ^= 1
		if _, err := OpenLog(op.pub, ms); err == nil {
			t.Fatal("OpenLog must reject a store with a mutated entry")
		}
	})

	t.Run("swapped entries", func(t *testing.T) {
		// Entry 1 corrects entry 0; swapping them forward-references.
		ms := NewMemStore()
		l, err := OpenLog(op.pub, ms)
		if err != nil {
			t.Fatalf("OpenLog: %v", err)
		}
		e0 := sealedEntry(t, id, a, b, contentN(0), Hash{}, testInstant)
		if _, err := l.Append(e0); err != nil {
			t.Fatalf("Append: %v", err)
		}
		e1 := sealedEntry(t, id, a, b, contentN(1), e0.ID(), testInstant)
		if _, err := l.Append(e1); err != nil {
			t.Fatalf("Append: %v", err)
		}
		ms.entries[0], ms.entries[1] = ms.entries[1], ms.entries[0]
		if _, err := OpenLog(op.pub, ms); err == nil {
			t.Fatal("OpenLog must reject a store whose reorder breaks correction order")
		}
	})

	t.Run("foreign entry inserted", func(t *testing.T) {
		_, ms, _ := buildLog(t, op, a, b, 2)
		foreign := sealedEntry(t, LogID(other.pub), a, b, contentN(9), Hash{}, testInstant)
		ms.entries = append(ms.entries, foreign)
		if _, err := OpenLog(op.pub, ms); err == nil {
			t.Fatal("OpenLog must reject a store containing a foreign-log entry")
		}
	})

	t.Run("duplicate entry inserted", func(t *testing.T) {
		_, ms, _ := buildLog(t, op, a, b, 2)
		ms.entries = append(ms.entries, ms.entries[0])
		if _, err := OpenLog(op.pub, ms); err == nil {
			t.Fatal("OpenLog must reject a store containing a duplicate leaf")
		}
	})
}

func TestCheckpointSignVerify(t *testing.T) {
	op, other := newParty(t), newParty(t)

	l, err := OpenLog(op.pub, NewMemStore())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	cp := l.Checkpoint(testInstant)
	if cp.Size != 0 {
		t.Fatalf("empty-log checkpoint Size = %d, want 0", cp.Size)
	}
	if cp.Head != LogID(op.pub) {
		t.Fatal("empty-log checkpoint Head must equal the LogID seed")
	}
	cp.Sign(op.priv)
	if !cp.Verify(op.pub) {
		t.Fatal("checkpoint must Verify under the operator key")
	}
	if cp.Verify(other.pub) {
		t.Fatal("checkpoint must not Verify under another key")
	}

	relabeled := cp
	relabeled.Log = LogID(other.pub)
	if relabeled.Verify(op.pub) {
		t.Fatal("checkpoint with overwritten Log must not Verify")
	}

	// Isolate the log-binding check: other signs a checkpoint naming op's
	// log; the signature is valid but the binding must fail.
	bound := Checkpoint{Log: LogID(op.pub), Size: 0, Head: LogID(op.pub), IssuedAt: testInstant}
	bound.Sign(other.priv)
	if bound.Verify(other.pub) {
		t.Fatal("checkpoint must bind cp.Log == LogID(operator); replay across logs must fail")
	}
}

func TestInclusionExhaustive(t *testing.T) {
	op, other := newParty(t), newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)

	ms := NewMemStore()
	l, err := OpenLog(op.pub, ms)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	var entries []Entry
	appendN := func(n int) {
		for i := 0; i < n; i++ {
			e := sealedEntry(t, id, a, b, contentN(byte(len(entries))), Hash{}, testInstant)
			if _, err := l.Append(e); err != nil {
				t.Fatalf("Append: %v", err)
			}
			entries = append(entries, e)
		}
	}
	prove := func(size uint64) (Checkpoint, []Proof) {
		cp := l.Checkpoint(testInstant)
		cp.Sign(op.priv)
		proofs := make([]Proof, size)
		for seq := uint64(0); seq < size; seq++ {
			p, err := l.Prove(seq)
			if err != nil {
				t.Fatalf("Prove(%d): %v", seq, err)
			}
			proofs[seq] = p
		}
		return cp, proofs
	}

	appendN(2)
	cp2, proofs2 := prove(2)
	appendN(3)
	cp5, proofs5 := prove(5)

	for _, tc := range []struct {
		cp     Checkpoint
		proofs []Proof
	}{{cp2, proofs2}, {cp5, proofs5}} {
		for seq, p := range tc.proofs {
			if !VerifyInclusion(entries[seq], p, tc.cp, op.pub) {
				t.Fatalf("inclusion of entry %d under size-%d checkpoint must verify", seq, tc.cp.Size)
			}
			if got := tc.cp.Size - 1 - uint64(len(p.Links)); got != uint64(seq) {
				t.Fatalf("proof position = %d, want %d", got, seq)
			}
		}
	}

	// A dishonest operator hand-chains a half-sealed entry and signs a
	// checkpoint over it; the one-call verifier still rejects it.
	half, err := NewEntry(id, a.pub, b.pub, contentN(99), Hash{}, testInstant)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if err := half.Seal(a.priv); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	dishonest := Checkpoint{
		Log:      id,
		Size:     cp5.Size + 1,
		Head:     chainStep(cp5.Head, half.ID()),
		IssuedAt: testInstant,
	}
	dishonest.Sign(op.priv)
	if !dishonest.Verify(op.pub) {
		t.Fatal("setup: dishonest checkpoint should carry a valid operator signature")
	}
	if VerifyInclusion(half, Proof{Prior: cp5.Head}, dishonest, op.pub) {
		t.Fatal("a half-sealed entry must never verify as included, even hand-chained by the operator")
	}

	// A foreign entry (another operator's log) never verifies here.
	foreign := sealedEntry(t, LogID(other.pub), a, b, contentN(98), Hash{}, testInstant)
	if VerifyInclusion(foreign, proofs5[0], cp5, op.pub) {
		t.Fatal("a foreign-log entry must not verify as included")
	}

	// Truncated links.
	trunc := Proof{Prior: proofs5[0].Prior, Links: proofs5[0].Links[:len(proofs5[0].Links)-1]}
	if VerifyInclusion(entries[0], trunc, cp5, op.pub) {
		t.Fatal("a truncated Links slice must not verify")
	}

	// Wrong prior.
	wrongPrior := proofs5[1]
	wrongPrior.Prior[0] ^= 1
	if VerifyInclusion(entries[1], wrongPrior, cp5, op.pub) {
		t.Fatal("a wrong Prior must not verify")
	}

	// Wrong operator key.
	if VerifyInclusion(entries[0], proofs5[0], cp5, other.pub) {
		t.Fatal("inclusion must not verify under the wrong operator key")
	}

	// Checkpoint from a different log.
	otherLog, err := OpenLog(other.pub, NewMemStore())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	otherCP := otherLog.Checkpoint(testInstant)
	otherCP.Sign(other.priv)
	if VerifyInclusion(entries[0], proofs5[0], otherCP, other.pub) {
		t.Fatal("inclusion must not verify against a checkpoint from a different log")
	}
}

func TestConsistency(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)

	ms := NewMemStore()
	l, err := OpenLog(op.pub, ms)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	sign := func(cp Checkpoint) Checkpoint {
		cp.Sign(op.priv)
		return cp
	}
	cp0 := sign(l.Checkpoint(testInstant))

	var entries []Entry
	for i := 0; i < 5; i++ {
		e := sealedEntry(t, id, a, b, contentN(byte(i)), Hash{}, testInstant)
		if _, err := l.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
		entries = append(entries, e)
	}
	// Rebuild checkpoints at sizes 2 and 5 by replaying a second store.
	ms2 := NewMemStore()
	l2, err := OpenLog(op.pub, ms2)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	var cp2 Checkpoint
	for i, e := range entries {
		if _, err := l2.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if i == 1 {
			cp2 = sign(l2.Checkpoint(testInstant))
		}
	}
	cp5 := sign(l.Checkpoint(testInstant))

	links, err := l.LeavesSince(2)
	if err != nil {
		t.Fatalf("LeavesSince(2): %v", err)
	}
	if !VerifyConsistency(cp2, cp5, links, op.pub) {
		t.Fatal("honest extension from size 2 to 5 must verify")
	}
	all, err := l.LeavesSince(0)
	if err != nil {
		t.Fatalf("LeavesSince(0): %v", err)
	}
	if !VerifyConsistency(cp0, cp5, all, op.pub) {
		t.Fatal("consistency from the empty-log checkpoint must accept the full leaf sequence")
	}
	if VerifyConsistency(cp5, cp2, nil, op.pub) {
		t.Fatal("newer.Size < older.Size must never verify")
	}
	if VerifyConsistency(cp5, cp2, links, op.pub) {
		t.Fatal("newer.Size < older.Size must never verify regardless of links")
	}

	// Fork: the operator rewrites entry 1 (inside cp2's history) and
	// extends to size 5. No links slice can reconcile cp2 with the fork.
	msF := NewMemStore()
	lf, err := OpenLog(op.pub, msF)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if _, err := lf.Append(entries[0]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	for i := 0; i < 4; i++ {
		e := sealedEntry(t, id, a, b, contentN(byte(100+i)), Hash{}, testInstant)
		if _, err := lf.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	cpFork5 := sign(lf.Checkpoint(testInstant))
	forkSince2, err := lf.LeavesSince(2)
	if err != nil {
		t.Fatalf("LeavesSince: %v", err)
	}
	for name, candidate := range map[string][]Hash{
		"fork LeavesSince(2)":   forkSince2,
		"honest LeavesSince(2)": links,
		"empty":                 nil,
		"full fork leaves":      mustLeaves(t, lf, 0),
	} {
		if VerifyConsistency(cp2, cpFork5, candidate, op.pub) {
			t.Fatalf("fork rewriting checkpointed history must fail VerifyConsistency (links: %s)", name)
		}
	}
	// Same-size fork against the honest size-5 checkpoint.
	if VerifyConsistency(cp5, cpFork5, nil, op.pub) {
		t.Fatal("a same-size fork must fail VerifyConsistency")
	}
}

func mustLeaves(t *testing.T, l *Log, since uint64) []Hash {
	t.Helper()
	leaves, err := l.LeavesSince(since)
	if err != nil {
		t.Fatalf("LeavesSince(%d): %v", since, err)
	}
	return leaves
}
