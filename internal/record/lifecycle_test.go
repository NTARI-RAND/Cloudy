package record

import (
	"testing"
	"time"
)

var lifeInstant = time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

func lifeTransition(log Hash, claim byte, kind TransitionKind, at time.Time) Transition {
	return Transition{
		Log:      log,
		Claim:    HashContent([]byte{claim}),
		Kind:     kind,
		Artifact: HashContent([]byte{claim, byte(kind)}),
		Exchange: HashContent([]byte{claim, 0xEE}),
		At:       at,
	}
}

func TestLifecycleStateMachine(t *testing.T) {
	op := newParty(t)
	id := LifecycleLogID(op.pub)
	l, err := OpenLifecycleLog(op.pub, NewMemTransitionStore())
	if err != nil {
		t.Fatalf("OpenLifecycleLog: %v", err)
	}

	// A claim's first transition must be its filing.
	if _, err := l.Append(lifeTransition(id, 1, KindAdjudicated, lifeInstant)); err == nil {
		t.Fatal("adjudication before filing must be refused")
	}
	if _, err := l.Append(lifeTransition(id, 1, KindFiled, lifeInstant)); err != nil {
		t.Fatalf("filing: %v", err)
	}
	// A claim files exactly once.
	if _, err := l.Append(lifeTransition(id, 1, KindFiled, lifeInstant.Add(time.Minute))); err == nil {
		t.Fatal("double filing must be refused")
	}
	// Adjudication may recur before resolution.
	if _, err := l.Append(lifeTransition(id, 1, KindAdjudicated, lifeInstant.Add(2*time.Minute))); err != nil {
		t.Fatalf("first adjudication: %v", err)
	}
	if _, err := l.Append(lifeTransition(id, 1, KindAdjudicated, lifeInstant.Add(3*time.Minute))); err != nil {
		t.Fatalf("second adjudication: %v", err)
	}
	// Seal before resolution must be refused — a clock never force-seals.
	if _, err := l.Append(lifeTransition(id, 1, KindSealed, lifeInstant.Add(4*time.Minute))); err == nil {
		t.Fatal("seal before resolution must be refused")
	}
	if _, err := l.Append(lifeTransition(id, 1, KindResolved, lifeInstant.Add(5*time.Minute))); err != nil {
		t.Fatalf("resolution: %v", err)
	}
	// Adjudication after resolution must be refused.
	if _, err := l.Append(lifeTransition(id, 1, KindAdjudicated, lifeInstant.Add(6*time.Minute))); err == nil {
		t.Fatal("adjudication after resolution must be refused")
	}
	if _, err := l.Append(lifeTransition(id, 1, KindSealed, lifeInstant.Add(7*time.Minute))); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if k, ok := l.State(HashContent([]byte{1})); !ok || k != KindSealed {
		t.Fatalf("state = %v ok=%v, want sealed", k, ok)
	}
	if got := len(l.Claim(HashContent([]byte{1}))); got != 5 {
		t.Fatalf("claim transition count = %d, want 5", got)
	}

	// A second claim's dwell is readable: filed, never resolved.
	if _, err := l.Append(lifeTransition(id, 2, KindFiled, lifeInstant)); err != nil {
		t.Fatalf("second claim filing: %v", err)
	}
	if k, ok := l.State(HashContent([]byte{2})); !ok || k != KindFiled {
		t.Fatalf("unresolved claim state = %v, want filed (dwell readable, never force-sealed)", k)
	}

	// Structural gates.
	bad := lifeTransition(id, 3, KindFiled, lifeInstant)
	bad.Claim = Hash{}
	if _, err := l.Append(bad); err == nil {
		t.Fatal("zero claim must be refused")
	}
	bad = lifeTransition(id, 3, KindFiled, lifeInstant)
	bad.Exchange = Hash{}
	if _, err := l.Append(bad); err == nil {
		t.Fatal("zero exchange must be refused")
	}
	foreign := lifeTransition(LifecycleLogID(newParty(t).pub), 3, KindFiled, lifeInstant)
	if _, err := l.Append(foreign); err == nil {
		t.Fatal("foreign-log transition must be refused")
	}
	dup := lifeTransition(id, 2, KindFiled, lifeInstant)
	if _, err := l.Append(dup); err == nil {
		t.Fatal("duplicate transition (same claim files once) must be refused")
	}

	// Replay re-verifies: the same store reopens to the same tree.
	// (State-machine order is enforced on replay through the same gates.)
	reopened, err := OpenLifecycleLog(op.pub, l.store.(*MemTransitionStore))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.Checkpoint(lifeInstant).Head != l.Checkpoint(lifeInstant).Head {
		t.Fatal("replayed lifecycle log head differs")
	}
}

func TestLifecycleCheckpointDisjointFromDialog(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)

	dialog, err := OpenLog(op.pub, NewMemStore())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	e := sealedEntry(t, LogID(op.pub), a, b, contentN(7), Hash{}, lifeInstant)
	if _, err := dialog.Append(e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	life, err := OpenLifecycleLog(op.pub, NewMemTransitionStore())
	if err != nil {
		t.Fatalf("OpenLifecycleLog: %v", err)
	}
	if _, err := life.Append(lifeTransition(LifecycleLogID(op.pub), 9, KindFiled, lifeInstant)); err != nil {
		t.Fatalf("Append transition: %v", err)
	}

	dcp := dialog.Checkpoint(lifeInstant)
	dcp.Sign(op.priv)
	lcp := life.Checkpoint(lifeInstant)
	lcp.Sign(op.priv)

	if !dcp.Verify(op.pub) || !lcp.VerifyAs(op.pub, LifecycleLogID(op.pub)) {
		t.Fatal("both checkpoints must verify under their own identities")
	}
	// Cross-binding is dead in both directions.
	if dcp.VerifyAs(op.pub, LifecycleLogID(op.pub)) {
		t.Fatal("a dialog checkpoint must never verify as a lifecycle checkpoint")
	}
	if lcp.Verify(op.pub) {
		t.Fatal("a lifecycle checkpoint must never verify as a dialog checkpoint")
	}

	// A witness serves both logs, keyed separately, and refuses cross-log use.
	w := NewWitness(newParty(t).priv)
	if _, err := w.CountersignAs(lcp, op.pub, LifecycleLogID(op.pub), nil); err != nil {
		t.Fatalf("CountersignAs lifecycle: %v", err)
	}
	if _, err := w.Countersign(dcp, op.pub, nil); err != nil {
		t.Fatalf("Countersign dialog: %v", err)
	}
	if _, err := w.CountersignAs(dcp, op.pub, LifecycleLogID(op.pub), nil); err == nil {
		t.Fatal("a witness must refuse a dialog checkpoint presented as lifecycle")
	}

	// Lifecycle consistency rides the same machinery.
	if _, err := life.Append(lifeTransition(LifecycleLogID(op.pub), 9, KindResolved, lifeInstant.Add(time.Minute))); err != nil {
		t.Fatalf("Append: %v", err)
	}
	lcp2 := life.Checkpoint(lifeInstant.Add(time.Minute))
	lcp2.Sign(op.priv)
	proof, err := life.ProveConsistency(1)
	if err != nil {
		t.Fatalf("ProveConsistency: %v", err)
	}
	if !VerifyConsistencyAs(lcp, lcp2, proof, op.pub, LifecycleLogID(op.pub)) {
		t.Fatal("lifecycle consistency must verify")
	}
	// Inclusion of a transition under the lifecycle checkpoint.
	p, err := life.Prove(0)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	tr, err := life.store.At(0)
	if err != nil {
		t.Fatalf("At: %v", err)
	}
	root, ok := rootFromPath(tr.ID(), p.Seq, lcp2.Size, p.Path)
	if !ok || root != lcp2.Head {
		t.Fatal("lifecycle inclusion proof must recompute the head")
	}
}

func TestFilingIntake(t *testing.T) {
	filer := newParty(t)
	witness := newParty(t)
	operator := newParty(t)

	f := FilingCommitment{
		Claim:    HashContent([]byte("claim")),
		Exchange: HashContent([]byte("exchange")),
		TypeHash: HashContent([]byte("trade-harm")),
		At:       lifeInstant,
		Filer:    filer.pub,
	}
	f.Sign(filer.priv)
	if !f.Verify() {
		t.Fatal("signed commitment must verify")
	}

	intake := NewFilingIntake(witness.priv)
	r, err := intake.Accept(f, lifeInstant.Add(time.Second))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !r.Verify() {
		t.Fatal("receipt must verify")
	}
	if !r.IndependentOf(operator.pub) {
		t.Fatal("a third-party witness is independent of the operator")
	}
	// The operator running its own intake is the labeled stand-in.
	opIntake := NewFilingIntake(operator.priv)
	r2, err := opIntake.Accept(f, lifeInstant.Add(time.Second))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if r2.IndependentOf(operator.pub) {
		t.Fatal("an operator-run intake must label itself non-independent")
	}

	// Tampering is caught.
	bad := r
	bad.Commitment.Exchange[0] ^= 1
	if bad.Verify() {
		t.Fatal("tampered receipt must not verify")
	}
	// The intake refuses the filer's own key as witness.
	selfIntake := NewFilingIntake(filer.priv)
	if _, err := selfIntake.Accept(f, lifeInstant); err == nil {
		t.Fatal("an intake witness never accepts its own filing")
	}
	// An unsigned commitment is refused.
	unsigned := f
	unsigned.Signature = nil
	if _, err := intake.Accept(unsigned, lifeInstant); err == nil {
		t.Fatal("an unsigned commitment must be refused")
	}
}
