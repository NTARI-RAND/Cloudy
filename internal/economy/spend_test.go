package economy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"
)

// seedKey derives a deterministic keypair from a repeated seed byte.
func seedKey(seed byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	var s [ed25519.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

// canonBuilder reconstructs the documented canonical layout independently of
// the canon package, so these tests fail if either the field order or the
// underlying encoding drifts.
type canonBuilder struct{ b []byte }

func (c *canonBuilder) count(n int) {
	var tmp [binary.MaxVarintLen64]byte
	m := binary.PutUvarint(tmp[:], uint64(n))
	c.b = append(c.b, tmp[:m]...)
}

func (c *canonBuilder) str(s string) {
	c.count(len(s))
	c.b = append(c.b, s...)
}

func (c *canonBuilder) bytes(p []byte) {
	c.count(len(p))
	c.b = append(c.b, p...)
}

func (c *canonBuilder) u64(v uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	c.b = append(c.b, tmp[:]...)
}

func (c *canonBuilder) timeNano(t time.Time) {
	c.u64(uint64(t.UTC().UnixNano()))
}

func fixedSpend() Spend {
	var from, to, ex [32]byte
	for i := range from {
		from[i] = 0x11
		to[i] = 0x22
		ex[i] = 0x33
	}
	return Spend{
		Platform:     "cloudy-test",
		From:         AccountID(from),
		To:           AccountID(to),
		Amount:       42,
		ExchangeHash: ex,
		IssuedAt:     time.Unix(1700000000, 123456789).UTC(),
		Nonce:        7,
	}
}

func TestSpendCanonicalBytesStable(t *testing.T) {
	s := fixedSpend()

	got := s.CanonicalBytes()
	if !bytes.Equal(got, s.CanonicalBytes()) {
		t.Fatal("CanonicalBytes is not stable across calls")
	}

	// Independent reconstruction of the documented layout.
	var want canonBuilder
	want.str("cloudy/economy/spend/v0")
	want.str(s.Platform)
	want.bytes(s.From[:])
	want.bytes(s.To[:])
	want.u64(uint64(s.Amount))
	want.bytes(s.ExchangeHash[:])
	want.timeNano(s.IssuedAt)
	want.u64(s.Nonce)
	if !bytes.Equal(got, want.b) {
		t.Fatalf("CanonicalBytes drifted from documented layout:\n got %x\nwant %x", got, want.b)
	}

	var prefix canonBuilder
	prefix.str("cloudy/economy/spend/v0")
	if !bytes.HasPrefix(got, prefix.b) {
		t.Fatal("CanonicalBytes does not begin with the length-prefixed domain tag")
	}

	// Signature exclusion: setting Signature must not change the bytes.
	s.Signature = bytes.Repeat([]byte{0xFF}, ed25519.SignatureSize)
	if !bytes.Equal(got, s.CanonicalBytes()) {
		t.Fatal("Signature leaked into CanonicalBytes")
	}
}

func TestSpendSignVerify(t *testing.T) {
	priv, pub := seedKey(0x01)
	_, otherPub := seedKey(0x02)

	s := fixedSpend()
	s.Sign(priv)

	if !s.Verify(pub) {
		t.Fatal("valid payer signature did not verify")
	}
	if s.Verify(otherPub) {
		t.Fatal("signature verified under a different key")
	}

	// Wrong-length signatures are rejected before ed25519.Verify.
	short := s
	short.Signature = s.Signature[:ed25519.SignatureSize-1]
	if short.Verify(pub) {
		t.Fatal("wrong-length signature verified")
	}
	empty := s
	empty.Signature = nil
	if empty.Verify(pub) {
		t.Fatal("missing signature verified")
	}
}

func TestSpendTamperDetection(t *testing.T) {
	priv, pub := seedKey(0x03)

	tests := []struct {
		name   string
		mutate func(*Spend)
	}{
		{"Platform", func(s *Spend) { s.Platform = "cloudy-other" }},
		{"From", func(s *Spend) { s.From[0] ^= 0x01 }},
		{"To", func(s *Spend) { s.To[0] ^= 0x01 }},
		{"Amount", func(s *Spend) { s.Amount++ }},
		{"ExchangeHash", func(s *Spend) { s.ExchangeHash[31] ^= 0x01 }},
		{"IssuedAt", func(s *Spend) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) }},
		{"Nonce", func(s *Spend) { s.Nonce++ }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := fixedSpend()
			s.Sign(priv)
			if !s.Verify(pub) {
				t.Fatal("baseline spend did not verify")
			}
			tc.mutate(&s)
			if s.Verify(pub) {
				t.Fatalf("mutating %s after signing was not detected", tc.name)
			}
		})
	}
}

func TestAccountIDPlatformScoped(t *testing.T) {
	_, pub := seedKey(0x04)

	a := AccountIDFor("cloudy", pub)
	b := AccountIDFor("other", pub)
	if a == b {
		t.Fatal("same key produced identical account IDs on different platforms; cross-platform correlation possible")
	}
	if a != AccountIDFor("cloudy", pub) {
		t.Fatal("AccountIDFor is not deterministic for the same inputs")
	}

	_, pub2 := seedKey(0x05)
	if a == AccountIDFor("cloudy", pub2) {
		t.Fatal("different keys produced identical account IDs")
	}
}
