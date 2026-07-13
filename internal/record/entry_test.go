package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"
)

// party bundles one member's keypair for tests.
type party struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newParty(t *testing.T) party {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return party{pub: pub, priv: priv}
}

// sealedEntry builds and fully dual-seals an entry between p1 and p2.
func sealedEntry(t *testing.T, log Hash, p1, p2 party, content, corrects Hash, at time.Time) Entry {
	t.Helper()
	e, err := NewEntry(log, p1.pub, p2.pub, content, corrects, at)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if err := e.Seal(p1.priv); err != nil {
		t.Fatalf("Seal(proposer): %v", err)
	}
	if err := e.Seal(p2.priv); err != nil {
		t.Fatalf("Seal(acceptor): %v", err)
	}
	return e
}

var testInstant = time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

func TestSealRoundTrip(t *testing.T) {
	a, b, stranger := newParty(t), newParty(t), newParty(t)
	log := LogID(newParty(t).pub)
	content := HashContent([]byte("narrative"))

	e := sealedEntry(t, log, a, b, content, Hash{}, testInstant)
	if !e.Verify() {
		t.Fatal("fully sealed entry must Verify")
	}

	unsealed, err := NewEntry(log, a.pub, b.pub, content, Hash{}, testInstant)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if unsealed.Verify() {
		t.Fatal("unsealed entry must not Verify")
	}

	half := unsealed
	if err := half.Seal(a.priv); err != nil {
		t.Fatalf("Seal(proposer): %v", err)
	}
	if half.Verify() {
		t.Fatal("proposer-only half-sealed entry must not Verify")
	}

	half2 := unsealed
	if err := half2.Seal(b.priv); err != nil {
		t.Fatalf("Seal(acceptor): %v", err)
	}
	if half2.Verify() {
		t.Fatal("acceptor-only half-sealed entry must not Verify")
	}

	other := unsealed
	if err := other.Seal(stranger.priv); err == nil {
		t.Fatal("Seal with a key that is neither party must error")
	}

	if _, err := NewEntry(log, a.pub, a.pub, content, Hash{}, testInstant); err == nil {
		t.Fatal("NewEntry with proposer == acceptor must error (no self-dialog)")
	}
	if _, err := NewEntry(log, a.pub[:16], b.pub, content, Hash{}, testInstant); err == nil {
		t.Fatal("NewEntry with malformed proposer key must error")
	}
	if _, err := NewEntry(log, a.pub, b.pub[:16], content, Hash{}, testInstant); err == nil {
		t.Fatal("NewEntry with malformed acceptor key must error")
	}
}

func TestTamperDetection(t *testing.T) {
	a, b := newParty(t), newParty(t)
	log := LogID(newParty(t).pub)
	content := HashContent([]byte("narrative"))

	cases := []struct {
		name   string
		mutate func(e *Entry)
	}{
		{"Log", func(e *Entry) { e.Log[0] ^= 1 }},
		{"Proposer", func(e *Entry) { e.Proposer[0] ^= 1 }},
		{"Acceptor", func(e *Entry) { e.Acceptor[0] ^= 1 }},
		{"Content", func(e *Entry) { e.Content[0] ^= 1 }},
		{"Corrects", func(e *Entry) { e.Corrects[0] ^= 1 }},
		{"Nonce", func(e *Entry) { e.Nonce[0] ^= 1 }},
		{"SealedAt", func(e *Entry) { e.SealedAt = e.SealedAt.Add(time.Second) }},
		{"PartySwap", func(e *Entry) { e.Proposer, e.Acceptor = e.Acceptor, e.Proposer }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := sealedEntry(t, log, a, b, content, Hash{}, testInstant)
			tc.mutate(&e)
			if e.Verify() {
				t.Fatalf("entry with tampered %s must not Verify", tc.name)
			}
		})
	}
}

func TestNonceDistinctness(t *testing.T) {
	a, b := newParty(t), newParty(t)
	log := LogID(newParty(t).pub)
	content := HashContent([]byte("identical agreement"))

	e1 := sealedEntry(t, log, a, b, content, Hash{}, testInstant)
	e2 := sealedEntry(t, log, a, b, content, Hash{}, testInstant)
	if e1.Nonce == e2.Nonce {
		t.Fatal("two entries from NewEntry must draw distinct nonces")
	}
	if e1.ID() == e2.ID() {
		t.Fatal("textually identical covenants must have distinct leaf IDs")
	}
}

func TestDomainSeparation(t *testing.T) {
	op := newParty(t)
	w := newParty(t)
	a := newParty(t)

	// Operator checkpoint over an empty log.
	l, err := OpenLog(op.pub, NewMemStore())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	cp := l.Checkpoint(testInstant)
	cp.Sign(op.priv)
	if !cp.Verify(op.pub) {
		t.Fatal("signed checkpoint must Verify")
	}

	// An operator's checkpoint Signature never validates as a
	// Countersignature over the same checkpoint.
	posing := Countersignature{Witness: op.pub, Signature: cp.Signature}
	if posing.Verify(cp) {
		t.Fatal("checkpoint signature must not verify as a witness countersignature")
	}

	// A witness cosignature is not a signature over the checkpoint's raw
	// canonical bytes (the witness tag is live).
	wit := NewWitness(w.priv)
	cs, err := wit.Countersign(cp, op.pub, nil)
	if err != nil {
		t.Fatalf("Countersign: %v", err)
	}
	if ed25519.Verify(w.pub, cp.CanonicalBytes(), cs.Signature) {
		t.Fatal("countersignature must not verify over untagged checkpoint bytes")
	}

	// An entry seal (operator as proposer) never verifies as a checkpoint
	// signature.
	e := sealedEntry(t, LogID(op.pub), op, a, HashContent([]byte("x")), Hash{}, testInstant)
	cp2 := cp
	cp2.Signature = e.ProposerSeal
	if cp2.Verify(op.pub) {
		t.Fatal("entry seal must not verify as a checkpoint signature")
	}

	// HashContent is domain-separated from bare sha256.
	x := []byte("content bytes")
	if HashContent(x) == Hash(sha256.Sum256(x)) {
		t.Fatal("HashContent must differ from bare sha256 (content tag is live)")
	}

	// LogID is domain-separated from bare sha256 of the key.
	if LogID(op.pub) == Hash(sha256.Sum256(op.pub)) {
		t.Fatal("LogID must differ from bare sha256 of the operator key (chain tag is live)")
	}
}

func TestUTCNormalization(t *testing.T) {
	a, b := newParty(t), newParty(t)
	log := LogID(newParty(t).pub)
	content := HashContent([]byte("narrative"))

	// A monotonic-bearing, non-UTC instant.
	loc := time.FixedZone("UTC+7", 7*3600)
	at := time.Now().In(loc)

	e := sealedEntry(t, log, a, b, content, Hash{}, at)
	if !e.Verify() {
		t.Fatal("entry sealed with non-UTC SealedAt must Verify")
	}

	round := e
	round.SealedAt = round.SealedAt.UTC().Round(0) // drop zone and monotonic reading
	if !round.Verify() {
		t.Fatal("entry must still Verify after a UTC round trip of SealedAt")
	}
	if !bytes.Equal(e.CanonicalBytes(), round.CanonicalBytes()) {
		t.Fatal("canonical bytes must be stable across a UTC round trip")
	}
	if e.ID() != round.ID() {
		t.Fatal("leaf ID must be stable across a UTC round trip")
	}
}

func TestHashContentDeterminism(t *testing.T) {
	if HashContent([]byte("same")) != HashContent([]byte("same")) {
		t.Fatal("HashContent must be deterministic")
	}
	if HashContent([]byte("one")) == HashContent([]byte("two")) {
		t.Fatal("HashContent must differ on different content")
	}
}
