package record

import (
	"crypto/ed25519"
	"testing"
)

// witnessFixture builds an operator log with five entries and signed
// checkpoints at sizes 0, 2, and 5, plus the honest extension evidence.
type witnessFixture struct {
	op            party
	cp0, cp2, cp5 Checkpoint
	links2to5     []Hash
	forkSameSize  Checkpoint // size 2, different head, validly operator-signed
}

func newWitnessFixture(t *testing.T) witnessFixture {
	t.Helper()
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)

	l, err := OpenLog(op.pub, NewMemStore())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	sign := func(cp Checkpoint) Checkpoint {
		cp.Sign(op.priv)
		return cp
	}
	f := witnessFixture{op: op}
	f.cp0 = sign(l.Checkpoint(testInstant))
	for i := 0; i < 5; i++ {
		e := sealedEntry(t, id, a, b, contentN(byte(i)), Hash{}, testInstant)
		if _, err := l.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if i == 1 {
			f.cp2 = sign(l.Checkpoint(testInstant))
		}
	}
	f.cp5 = sign(l.Checkpoint(testInstant))
	proof, err := l.ProveConsistency(2)
	if err != nil {
		t.Fatalf("ProveConsistency(2): %v", err)
	}
	f.links2to5 = proof

	fork := f.cp2
	fork.Head[0] ^= 1
	f.forkSameSize = sign(fork)
	return f
}

func TestWitnessStatefulness(t *testing.T) {
	f := newWitnessFixture(t)
	w := NewWitness(newParty(t).priv)

	// Trust on first checkpoint.
	cs, err := w.Countersign(f.cp2, f.op.pub, nil)
	if err != nil {
		t.Fatalf("first Countersign (TOFU): %v", err)
	}
	if !cs.Verify(f.cp2) {
		t.Fatal("countersignature must verify over the checkpoint")
	}

	// Rollback refused.
	if _, err := w.Countersign(f.cp0, f.op.pub, nil); err == nil {
		t.Fatal("a smaller-size checkpoint must be refused (rollback)")
	}

	// Same-size fork refused.
	if _, err := w.Countersign(f.forkSameSize, f.op.pub, nil); err == nil {
		t.Fatal("a same-size different-head checkpoint must be refused (fork)")
	}

	// Extension without evidence refused.
	if _, err := w.Countersign(f.cp5, f.op.pub, nil); err == nil {
		t.Fatal("an extension without leaf evidence must be refused")
	}

	// Honest extension with evidence succeeds and updates state.
	if _, err := w.Countersign(f.cp5, f.op.pub, f.links2to5); err != nil {
		t.Fatalf("honest extension: %v", err)
	}
	if _, err := w.Countersign(f.cp2, f.op.pub, nil); err == nil {
		t.Fatal("after advancing to size 5, size 2 must be refused (rollback)")
	}
	// Re-cosigning the exact same checkpoint is a harmless no-op extension.
	if _, err := w.Countersign(f.cp5, f.op.pub, nil); err != nil {
		t.Fatalf("re-cosigning the same checkpoint: %v", err)
	}

	// A witness never countersigns its own operator.
	self := NewWitness(f.op.priv)
	if _, err := self.Countersign(f.cp2, f.op.pub, nil); err == nil {
		t.Fatal("a witness must refuse its own operator")
	}

	// An invalid operator signature is refused even on first sight.
	bad := f.cp5
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[0] ^= 1
	fresh := NewWitness(newParty(t).priv)
	if _, err := fresh.Countersign(bad, f.op.pub, nil); err == nil {
		t.Fatal("a checkpoint with an invalid operator signature must be refused")
	}
}

func TestWitnessedCheckpoint(t *testing.T) {
	f := newWitnessFixture(t)
	w1, w2 := NewWitness(newParty(t).priv), NewWitness(newParty(t).priv)

	cs1, err := w1.Countersign(f.cp5, f.op.pub, nil)
	if err != nil {
		t.Fatalf("Countersign: %v", err)
	}
	cs2, err := w2.Countersign(f.cp5, f.op.pub, nil)
	if err != nil {
		t.Fatalf("Countersign: %v", err)
	}

	wc := WitnessedCheckpoint{Checkpoint: f.cp5, Countersignatures: []Countersignature{cs1, cs2}}
	if !wc.Verify(f.op.pub) {
		t.Fatal("two independent witnesses must verify")
	}
	if wc.StandIn(f.op.pub) {
		t.Fatal("two distinct witnesses are not a stand-in")
	}

	// A failing countersignature poisons the bundle.
	badCS := cs1
	badCS.Signature = append([]byte(nil), badCS.Signature...)
	badCS.Signature[0] ^= 1
	badBundle := WitnessedCheckpoint{Checkpoint: f.cp5, Countersignatures: []Countersignature{badCS, cs2}}
	if badBundle.Verify(f.op.pub) {
		t.Fatal("a bundle with an invalid countersignature must not verify")
	}

	// The operator posing as a witness (hand-crafted cosignature under the
	// witness tag) is rejected: an operator can never be its own witness.
	opCS := Countersignature{
		Witness:   f.op.pub,
		Signature: ed25519.Sign(f.op.priv, witnessPayload(f.cp5)),
	}
	if !opCS.Verify(f.cp5) {
		t.Fatal("setup: the hand-crafted cosignature itself should be cryptographically valid")
	}
	selfBundle := WitnessedCheckpoint{Checkpoint: f.cp5, Countersignatures: []Countersignature{opCS, cs2}}
	if selfBundle.Verify(f.op.pub) {
		t.Fatal("a bundle where a witness key equals the operator key must not verify")
	}

	// Duplicate witness keys are rejected.
	dupBundle := WitnessedCheckpoint{Checkpoint: f.cp5, Countersignatures: []Countersignature{cs1, cs1}}
	if dupBundle.Verify(f.op.pub) {
		t.Fatal("a bundle with a duplicated witness must not verify")
	}
	if !dupBundle.StandIn(f.op.pub) {
		t.Fatal("two cosignatures from one witness are one distinct witness: a stand-in")
	}

	// StandIn labeling.
	if !(WitnessedCheckpoint{Checkpoint: f.cp5}).StandIn(f.op.pub) {
		t.Fatal("zero witnesses is a stand-in")
	}
	one := WitnessedCheckpoint{Checkpoint: f.cp5, Countersignatures: []Countersignature{cs1}}
	if !one.StandIn(f.op.pub) {
		t.Fatal("one witness is a stand-in")
	}
	if !one.Verify(f.op.pub) {
		t.Fatal("a single-witness bundle still verifies; StandIn is the label, not a failure")
	}
}

// TestStandInCountsOnlyVerifiedCosigs is the regression test for the finding
// that StandIn built its distinct-key set from raw Witness fields without
// verifying the cosignatures: a bundle padded with two garbage
// countersignatures read as "federated" to any surface that rendered the
// label without also calling Verify. StandIn now counts only cosignatures
// that verify against the bundle's checkpoint and are independent of the
// operator.
func TestStandInCountsOnlyVerifiedCosigs(t *testing.T) {
	f := newWitnessFixture(t)

	garbage := func(seed byte) Countersignature {
		k := make([]byte, ed25519.PublicKeySize)
		s := make([]byte, ed25519.SignatureSize)
		for i := range k {
			k[i] = seed
		}
		for i := range s {
			s[i] = seed ^ 0xFF
		}
		return Countersignature{Witness: k, Signature: s}
	}
	w := NewWitness(newParty(t).priv)
	cs, err := w.Countersign(f.cp5, f.op.pub, nil)
	if err != nil {
		t.Fatalf("Countersign: %v", err)
	}
	cs2over2, err := NewWitness(newParty(t).priv).Countersign(f.cp2, f.op.pub, nil)
	if err != nil {
		t.Fatalf("Countersign: %v", err)
	}
	// An operator-authored cosignature is cryptographically valid under the
	// witness tag but must never count toward independence.
	opCS := Countersignature{
		Witness:   f.op.pub,
		Signature: ed25519.Sign(f.op.priv, witnessPayload(f.cp5)),
	}

	tests := []struct {
		name    string
		cosigs  []Countersignature
		standIn bool
	}{
		{"two garbage cosignatures with distinct valid-length keys", []Countersignature{garbage(1), garbage(2)}, true},
		{"one real witness padded with garbage", []Countersignature{cs, garbage(3)}, true},
		{"operator posing as witness plus one real witness", []Countersignature{opCS, cs}, true},
		{"cosignature over a different checkpoint does not count", []Countersignature{cs, cs2over2}, true},
		{"one real witness alone", []Countersignature{cs}, true},
	}
	for _, tc := range tests {
		wc := WitnessedCheckpoint{Checkpoint: f.cp5, Countersignatures: tc.cosigs}
		if got := wc.StandIn(f.op.pub); got != tc.standIn {
			t.Errorf("%s: StandIn() = %v, want %v", tc.name, got, tc.standIn)
		}
	}
}

func TestCosignatureDomainSeparation(t *testing.T) {
	f := newWitnessFixture(t)
	w := NewWitness(newParty(t).priv)
	cs, err := w.Countersign(f.cp5, f.op.pub, nil)
	if err != nil {
		t.Fatalf("Countersign: %v", err)
	}

	// A cosignature is not an operator-style signature over the raw
	// checkpoint bytes.
	if ed25519.Verify(cs.Witness, f.cp5.CanonicalBytes(), cs.Signature) {
		t.Fatal("cosignature must not verify over untagged checkpoint bytes")
	}

	// An operator checkpoint signature is not a valid cosignature.
	posing := Countersignature{Witness: f.op.pub, Signature: f.cp5.Signature}
	if posing.Verify(f.cp5) {
		t.Fatal("an operator checkpoint signature must not validate as a countersignature")
	}
}
