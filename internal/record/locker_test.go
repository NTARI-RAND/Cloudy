package record

import (
	"bytes"
	"testing"
)

func TestLockerRoundTrip(t *testing.T) {
	lk := NewMemLocker()
	content := []byte("the identifying narrative of an exchange")

	h := lk.Put(content)
	if h != HashContent(content) {
		t.Fatal("Put must return HashContent of the stored bytes")
	}

	got, ok := lk.Get(h)
	if !ok || !bytes.Equal(got, content) {
		t.Fatal("Get must return the stored content")
	}

	lk.Erase(h)
	if _, ok := lk.Get(h); ok {
		t.Fatal("Get after Erase must miss")
	}

	if _, ok := lk.Get(HashContent([]byte("never stored"))); ok {
		t.Fatal("Get of never-stored content must miss")
	}
}

func TestErasureNeverDisturbsTheCommons(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)

	lk := NewMemLocker()
	content := []byte("member-local identifying content")
	ch := lk.Put(content)

	l, err := OpenLog(op.pub, NewMemStore())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	e := sealedEntry(t, id, a, b, ch, Hash{}, testInstant)
	seq, err := l.Append(e)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	cp := l.Checkpoint(testInstant)
	cp.Sign(op.priv)
	p, err := l.Prove(seq)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if !VerifyInclusion(e, p, cp, op.pub) {
		t.Fatal("setup: inclusion must verify before erasure")
	}

	lk.Erase(ch)
	if _, ok := lk.Get(ch); ok {
		t.Fatal("content must be gone after Erase")
	}
	if !VerifyInclusion(e, p, cp, op.pub) {
		t.Fatal("erasing member-local content must leave the inclusion proof fully verifiable — the commons never notices erasure")
	}
}
