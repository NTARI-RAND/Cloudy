package economy

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPolicyChangeCanonicalBytesStable(t *testing.T) {
	c := PolicyChange{
		Platform: "cloudy-test",
		Policy:   Policy{Mode: ModeCredit, DebitCap: 500},
		Version:  3,
		At:       time.Unix(1700000100, 987654321).UTC(),
	}

	got := c.CanonicalBytes()
	if !bytes.Equal(got, c.CanonicalBytes()) {
		t.Fatal("CanonicalBytes is not stable across calls")
	}

	var want canonBuilder
	want.str("cloudy/economy/policy/v0")
	want.str(c.Platform)
	want.str(string(c.Policy.Mode))
	want.u64(uint64(c.Policy.DebitCap))
	want.u64(c.Version)
	want.timeNano(c.At)
	if !bytes.Equal(got, want.b) {
		t.Fatalf("CanonicalBytes drifted from documented layout:\n got %x\nwant %x", got, want.b)
	}

	// Sigs exclusion: signing must not change the payload.
	priv, _ := seedKey(0x06)
	c.Sign(priv)
	c.Sign(priv)
	if !bytes.Equal(got, c.CanonicalBytes()) {
		t.Fatal("Sigs leaked into CanonicalBytes")
	}
}

func TestPolicyChangeQuorum(t *testing.T) {
	f := newFixture(t, ModeEscrow, 100)
	outsiderPriv, _ := seedKey(0x77)

	newChange := func() PolicyChange {
		return PolicyChange{
			Platform: f.genesis.Platform,
			Policy:   Policy{Mode: ModeCredit, DebitCap: 100},
			Version:  1,
			At:       time.Unix(1700000100, 0).UTC(),
		}
	}

	tests := []struct {
		name       string
		sign       func(*PolicyChange)
		wantVerify bool
	}{
		{"zero signatures", func(c *PolicyChange) {}, false},
		{"threshold minus one", func(c *PolicyChange) {
			c.Sign(f.stewards[0])
		}, false},
		{"non-steward signature does not count", func(c *PolicyChange) {
			c.Sign(f.stewards[0])
			c.Sign(outsiderPriv)
		}, false},
		{"duplicate steward counts once", func(c *PolicyChange) {
			c.Sign(f.stewards[0])
			c.Sign(f.stewards[0])
		}, false},
		{"wrong-length signature does not count", func(c *PolicyChange) {
			c.Sign(f.stewards[0])
			c.Sigs = append(c.Sigs, c.Sigs[0][:ed25519.SignatureSize-1])
		}, false},
		{"exact threshold distinct stewards", func(c *PolicyChange) {
			c.Sign(f.stewards[0])
			c.Sign(f.stewards[1])
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh ledger per row so Enact sees version 0.
			row := newFixture(t, ModeEscrow, 100)
			c := newChange()
			c.Platform = row.genesis.Platform
			tc.sign(&c)
			// Re-sign against the row genesis (stewards are the same seeded
			// keys, so signatures remain valid; assert anyway).
			if got := c.Verify(row.genesis); got != tc.wantVerify {
				t.Fatalf("Verify = %v, want %v", got, tc.wantVerify)
			}
			err := row.ledger.Enact(c)
			if tc.wantVerify {
				if err != nil {
					t.Fatalf("Enact of quorate change failed: %v", err)
				}
				if row.ledger.Policy().Mode != ModeCredit {
					t.Fatal("quorate change did not take effect")
				}
			} else {
				if !errors.Is(err, ErrQuorum) {
					t.Fatalf("Enact = %v, want ErrQuorum", err)
				}
				if row.ledger.Policy().Mode != ModeEscrow {
					t.Fatal("sub-quorum change altered policy")
				}
			}
		})
	}

	t.Run("version rollback", func(t *testing.T) {
		row := newFixture(t, ModeEscrow, 100)
		first := row.change(Policy{Mode: ModeCredit, DebitCap: 100}, 1, 2)
		if err := row.ledger.Enact(first); err != nil {
			t.Fatalf("initial enact failed: %v", err)
		}
		for _, v := range []uint64{1, 0} {
			c := row.change(Policy{Mode: ModeCredit, DebitCap: 200}, v, 2)
			if err := row.ledger.Enact(c); !errors.Is(err, ErrReplay) {
				t.Fatalf("Enact version %d = %v, want ErrReplay", v, err)
			}
		}
		if row.ledger.Policy().DebitCap != 100 {
			t.Fatal("rolled-back change altered policy")
		}
	})
}

func TestOpenValidatesGenesis(t *testing.T) {
	_, s0 := seedKey(0xA0)
	_, s1 := seedKey(0xA1)
	stewards := []ed25519.PublicKey{s0, s1}
	good := Genesis{
		Platform:  "cloudy-test",
		Stewards:  stewards,
		Threshold: 2,
		Policy:    Policy{Mode: ModeEscrow, DebitCap: 100},
	}

	tests := []struct {
		name   string
		mutate func(*Genesis)
	}{
		{"empty platform", func(g *Genesis) { g.Platform = "" }},
		{"threshold below one", func(g *Genesis) { g.Threshold = 0 }},
		{"threshold above steward count", func(g *Genesis) { g.Threshold = 3 }},
		{"unknown mode", func(g *Genesis) { g.Policy.Mode = "barter" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := good
			tc.mutate(&g)
			_, err := Open(g, mapDirectory{}, NewMemStore())
			if err == nil {
				t.Fatal("Open accepted an invalid genesis")
			}
			if !strings.HasPrefix(err.Error(), "economy:") {
				t.Fatalf("error %q lacks the package prefix", err)
			}
		})
	}

	t.Run("valid genesis opens", func(t *testing.T) {
		if _, err := Open(good, mapDirectory{}, NewMemStore()); err != nil {
			t.Fatalf("Open of valid genesis failed: %v", err)
		}
	})
}
