package dispute

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// --- shared test helpers (white-box: package dispute) ---

func genKeyT(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pub, priv
}

// ref builds a non-zero ExchangeRef filled with b.
func ref(b byte) ExchangeRef {
	var r ExchangeRef
	for i := range r {
		r[i] = b
	}
	return r
}

// stubAnchors is a configurable Anchors. When any is true it seals every
// reference; otherwise it seals only tuples explicitly added by seal.
type stubAnchors struct {
	any    bool
	sealed map[string]bool
}

func newStubAnchors() *stubAnchors { return &stubAnchors{sealed: map[string]bool{}} }

func tupleKey(ex ExchangeRef, c, r ed25519.PublicKey) string {
	return string(ex[:]) + "\x00" + string(c) + "\x00" + string(r)
}

func (a *stubAnchors) seal(ex ExchangeRef, c, r ed25519.PublicKey) {
	a.sealed[tupleKey(ex, c, r)] = true
	a.sealed[tupleKey(ex, r, c)] = true
}

func (a *stubAnchors) Sealed(ex ExchangeRef, c, r ed25519.PublicKey) bool {
	if a.any {
		return true
	}
	return a.sealed[tupleKey(ex, c, r)]
}

var _ Anchors = (*stubAnchors)(nil)

// mkOpening builds and signs an opening.
func mkOpening(t *testing.T, cPub ed25519.PublicKey, cKey ed25519.PrivateKey, rPub ed25519.PublicKey, ex ExchangeRef) Opening {
	t.Helper()
	o, err := NewOpening("cloudy", cPub, rPub, ex, [32]byte{}, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	if err := o.Sign(cKey); err != nil {
		t.Fatalf("Sign opening: %v", err)
	}
	return o
}

// fixture bundles a registry with two adjudicators and one member pair.
type fixture struct {
	reg     *Registry
	anchors *stubAnchors
	cPub    ed25519.PublicKey
	cKey    ed25519.PrivateKey
	rPub    ed25519.PublicKey
	rKey    ed25519.PrivateKey
	adj1    ed25519.PrivateKey
	adj2    ed25519.PrivateKey
	charter Charter
}

func newFixture(t *testing.T, threshold int) *fixture {
	t.Helper()
	cPub, cKey := genKeyT(t)
	rPub, rKey := genKeyT(t)
	a1Pub, a1 := genKeyT(t)
	a2Pub, a2 := genKeyT(t)
	anchors := newStubAnchors()
	charter := Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{a1Pub, a2Pub}, Threshold: threshold}
	reg, err := NewRegistry(charter, anchors, NewMemStore())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return &fixture{reg: reg, anchors: anchors, cPub: cPub, cKey: cKey, rPub: rPub, rKey: rKey, adj1: a1, adj2: a2, charter: charter}
}

// signedRuling builds an escrow or credit ruling and signs it with the given
// number of distinct adjudicators.
func (f *fixture) signRuling(r Ruling, signers int) Ruling {
	if signers >= 1 {
		r.Sign(f.adj1)
	}
	if signers >= 2 {
		r.Sign(f.adj2)
	}
	return r
}

// --- NewRegistry validation ---

func TestNewRegistryValidatesCharter(t *testing.T) {
	pub, _ := genKeyT(t)
	anchors := newStubAnchors()
	store := NewMemStore()
	cases := []struct {
		name    string
		charter Charter
		anchors Anchors
		store   Store
	}{
		{"empty platform", Charter{Platform: "", Adjudicators: []ed25519.PublicKey{pub}, Threshold: 1}, anchors, store},
		{"no adjudicators", Charter{Platform: "cloudy", Threshold: 1}, anchors, store},
		{"threshold zero", Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{pub}, Threshold: 0}, anchors, store},
		{"threshold exceeds roster", Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{pub}, Threshold: 2}, anchors, store},
		{"malformed key", Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{pub[:5]}, Threshold: 1}, anchors, store},
		{"nil anchors", Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{pub}, Threshold: 1}, nil, store},
		{"nil store", Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{pub}, Threshold: 1}, anchors, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, err := NewRegistry(tc.charter, tc.anchors, tc.store)
			if err == nil {
				t.Fatal("NewRegistry must reject a bad charter or nil dependency")
			}
			if reg != nil {
				t.Fatal("NewRegistry must return a nil Registry alongside the error")
			}
		})
	}
}

// --- Open gating ---

func TestOpenGates(t *testing.T) {
	f := newFixture(t, 2)
	ex := ref(0xA1)
	f.anchors.seal(ex, f.cPub, f.rPub)

	t.Run("unsigned opening rejected", func(t *testing.T) {
		o, err := NewOpening("cloudy", f.cPub, f.rPub, ex, [32]byte{}, time.Unix(1, 0).UTC())
		if err != nil {
			t.Fatalf("NewOpening: %v", err)
		}
		if _, err := f.reg.Open(o); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Open(unsigned) = %v, want ErrInvalid", err)
		}
	})
	t.Run("platform mismatch rejected", func(t *testing.T) {
		o, err := NewOpening("other", f.cPub, f.rPub, ex, [32]byte{}, time.Unix(1, 0).UTC())
		if err != nil {
			t.Fatalf("NewOpening: %v", err)
		}
		if err := o.Sign(f.cKey); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := f.reg.Open(o); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Open(wrong platform) = %v, want ErrInvalid", err)
		}
	})
	t.Run("unanchored exchange rejected", func(t *testing.T) {
		o := mkOpening(t, f.cPub, f.cKey, f.rPub, ref(0xBB)) // not sealed
		if _, err := f.reg.Open(o); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Open(unanchored) = %v, want ErrInvalid", err)
		}
	})
	t.Run("anchored opening admitted", func(t *testing.T) {
		o := mkOpening(t, f.cPub, f.cKey, f.rPub, ex)
		id, err := f.reg.Open(o)
		if err != nil {
			t.Fatalf("Open = %v, want admission", err)
		}
		if id != o.ID() {
			t.Fatal("Open must return the opening's ID as the DisputeID")
		}
		c, err := f.reg.Case(id)
		if err != nil {
			t.Fatalf("Case = %v", err)
		}
		if c.State() != StateOpen {
			t.Fatalf("state after Open = %v, want StateOpen", c.State())
		}
	})
}

func TestOpenRejectsSecondLiveCase(t *testing.T) {
	f := newFixture(t, 2)
	ex := ref(0xA1)
	f.anchors.seal(ex, f.cPub, f.rPub)

	if _, err := f.reg.Open(mkOpening(t, f.cPub, f.cKey, f.rPub, ex)); err != nil {
		t.Fatalf("first Open = %v", err)
	}
	// A different opening (fresh nonce) for the same (exchange, pair) while the
	// first is still open must be rejected as a duplicate live case.
	if _, err := f.reg.Open(mkOpening(t, f.cPub, f.cKey, f.rPub, ex)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second live Open = %v, want ErrDuplicate", err)
	}
}

// --- the state machine ---

func TestStateMachine(t *testing.T) {
	at := time.Unix(1_700_000_100, 0).UTC()

	// resolveRuling / withdrawal builders bound to a fixture+case are created
	// per-subtest since each needs a fresh open case.
	openCase := func(t *testing.T, f *fixture, ex ExchangeRef) (DisputeID, Opening) {
		t.Helper()
		f.anchors.seal(ex, f.cPub, f.rPub)
		o := mkOpening(t, f.cPub, f.cKey, f.rPub, ex)
		id, err := f.reg.Open(o)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return id, o
	}

	t.Run("open then rule -> resolved; second rule -> closed", func(t *testing.T) {
		f := newFixture(t, 2)
		id, _ := openCase(t, f, ref(0x01))
		r := f.signRuling(NewCreditRuling("cloudy", id, ref(0x01), FindingForComplainant, HarmUpheld, nil, [32]byte{}, at), 2)
		if err := f.reg.Rule(r); err != nil {
			t.Fatalf("Rule = %v, want admission", err)
		}
		c, _ := f.reg.Case(id)
		if c.State() != StateResolved {
			t.Fatalf("state = %v, want StateResolved", c.State())
		}
		if fnd, ok := c.Finding(); !ok || fnd != FindingForComplainant {
			t.Fatalf("Finding = (%v,%v), want (FindingForComplainant,true)", fnd, ok)
		}
		// A second ruling on a resolved case is closed.
		r2 := f.signRuling(NewCreditRuling("cloudy", id, ref(0x01), FindingForRespondent, HarmUpheld, nil, [32]byte{}, at), 2)
		if err := f.reg.Rule(r2); !errors.Is(err, ErrClosed) {
			t.Fatalf("second Rule = %v, want ErrClosed", err)
		}
	})

	t.Run("open then withdraw -> withdrawn; rule after -> closed", func(t *testing.T) {
		f := newFixture(t, 2)
		id, _ := openCase(t, f, ref(0x02))
		w := Withdrawal{Platform: "cloudy", Dispute: id, WithdrawnAt: at}
		w.Sign(f.cKey)
		if err := f.reg.Withdraw(w); err != nil {
			t.Fatalf("Withdraw = %v, want admission", err)
		}
		c, _ := f.reg.Case(id)
		if c.State() != StateWithdrawn {
			t.Fatalf("state = %v, want StateWithdrawn", c.State())
		}
		r := f.signRuling(NewCreditRuling("cloudy", id, ref(0x02), FindingForComplainant, HarmUpheld, nil, [32]byte{}, at), 2)
		if err := f.reg.Rule(r); !errors.Is(err, ErrClosed) {
			t.Fatalf("Rule after withdraw = %v, want ErrClosed", err)
		}
	})

	t.Run("withdraw by non-complainant -> unauthorized", func(t *testing.T) {
		f := newFixture(t, 2)
		id, _ := openCase(t, f, ref(0x03))
		w := Withdrawal{Platform: "cloudy", Dispute: id, WithdrawnAt: at}
		w.Sign(f.rKey) // respondent, not complainant
		if err := f.reg.Withdraw(w); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Withdraw by respondent = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("re-dispute after terminal admitted with new id", func(t *testing.T) {
		f := newFixture(t, 2)
		ex := ref(0x04)
		id1, _ := openCase(t, f, ex)
		w := Withdrawal{Platform: "cloudy", Dispute: id1, WithdrawnAt: at}
		w.Sign(f.cKey)
		if err := f.reg.Withdraw(w); err != nil {
			t.Fatalf("Withdraw = %v", err)
		}
		// After the terminal state, a fresh opening for the same pair/exchange is
		// admissible again (new nonce -> new DisputeID).
		o2 := mkOpening(t, f.cPub, f.cKey, f.rPub, ex)
		id2, err := f.reg.Open(o2)
		if err != nil {
			t.Fatalf("re-dispute Open = %v, want admission", err)
		}
		if id2 == id1 {
			t.Fatal("re-dispute must mint a distinct DisputeID")
		}
	})

	t.Run("rule/withdraw on unknown case -> invalid", func(t *testing.T) {
		f := newFixture(t, 2)
		unknown := DisputeID{9: 9}
		r := f.signRuling(NewCreditRuling("cloudy", unknown, ref(0x05), FindingForComplainant, HarmUpheld, nil, [32]byte{}, at), 2)
		if err := f.reg.Rule(r); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Rule(unknown) = %v, want ErrInvalid", err)
		}
		w := Withdrawal{Platform: "cloudy", Dispute: unknown, WithdrawnAt: at}
		w.Sign(f.cKey)
		if err := f.reg.Withdraw(w); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Withdraw(unknown) = %v, want ErrInvalid", err)
		}
	})
}

// --- Rule admission: escrow-vs-credit resolution paths ---

func TestRuleResolutionPaths(t *testing.T) {
	at := time.Unix(1_700_000_200, 0).UTC()

	build := func(f *fixture, id DisputeID, ex ExchangeRef) map[string]Ruling {
		return map[string]Ruling{
			"escrow ok":          NewEscrowRuling("cloudy", id, ex, FindingForComplainant, ActionRefundComplainant, 10, [32]byte{}, at),
			"credit harm upheld": NewCreditRuling("cloudy", id, ex, FindingForRespondent, HarmUpheld, nil, [32]byte{}, at),
			"credit with refund": NewCreditRuling("cloudy", id, ex, FindingForComplainant, HarmExpunged, &RefundDirective{Units: 3}, [32]byte{}, at),
		}
	}

	// Positive paths: each well-formed ruling with a quorum is admitted and
	// resolves the case with the expected remedy shape.
	for name := range map[string]bool{"escrow ok": true, "credit harm upheld": true, "credit with refund": true} {
		name := name
		t.Run("admit "+name, func(t *testing.T) {
			f := newFixture(t, 2)
			ex := ref(0x21)
			f.anchors.seal(ex, f.cPub, f.rPub)
			id, err := f.reg.Open(mkOpening(t, f.cPub, f.cKey, f.rPub, ex))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			r := f.signRuling(build(f, id, ex)[name], 2)
			if err := f.reg.Rule(r); err != nil {
				t.Fatalf("Rule(%s) = %v, want admission", name, err)
			}
			c, _ := f.reg.Case(id)
			rem, ok := c.Remedy()
			if !ok {
				t.Fatal("resolved case must expose a remedy")
			}
			switch name {
			case "escrow ok":
				if rem.Escalation == nil || rem.Harm != 0 || rem.Refund != nil {
					t.Fatalf("escrow remedy shape wrong: %+v", rem)
				}
			case "credit harm upheld":
				if rem.Escalation != nil || rem.Harm != HarmUpheld || rem.Refund != nil {
					t.Fatalf("credit remedy shape wrong: %+v", rem)
				}
			case "credit with refund":
				if rem.Escalation != nil || rem.Harm != HarmExpunged || rem.Refund == nil || rem.Refund.Units != 3 {
					t.Fatalf("credit+refund remedy shape wrong: %+v", rem)
				}
			}
		})
	}

	// Negative paths.
	neg := []struct {
		name    string
		make    func(f *fixture, id DisputeID, ex ExchangeRef) Ruling
		signers int
		wantErr error
	}{
		{
			"below quorum",
			func(f *fixture, id DisputeID, ex ExchangeRef) Ruling {
				return f.signRuling(NewCreditRuling("cloudy", id, ex, FindingForComplainant, HarmUpheld, nil, [32]byte{}, at), 1)
			},
			1, ErrUnauthorized,
		},
		{
			"escrow missing escalation",
			func(f *fixture, id DisputeID, ex ExchangeRef) Ruling {
				r := Ruling{Platform: "cloudy", Dispute: id, Exchange: ex, Mode: ModeEscrow, Finding: FindingForComplainant, RuledAt: at}
				return f.signRuling(r, 2)
			},
			2, ErrInvalid,
		},
		{
			"credit with escalation leak",
			func(f *fixture, id DisputeID, ex ExchangeRef) Ruling {
				r := Ruling{Platform: "cloudy", Dispute: id, Exchange: ex, Mode: ModeCredit, Finding: FindingForComplainant,
					Remedy: Remedy{Harm: HarmUpheld, Escalation: &Escalation{Action: ActionSplit, Units: 1}}, RuledAt: at}
				return f.signRuling(r, 2)
			},
			2, ErrInvalid,
		},
		{
			"exchange mismatch",
			func(f *fixture, id DisputeID, ex ExchangeRef) Ruling {
				return f.signRuling(NewCreditRuling("cloudy", id, ref(0xEE), FindingForComplainant, HarmUpheld, nil, [32]byte{}, at), 2)
			},
			2, ErrInvalid,
		},
		{
			"platform mismatch",
			func(f *fixture, id DisputeID, ex ExchangeRef) Ruling {
				return f.signRuling(NewCreditRuling("other", id, ex, FindingForComplainant, HarmUpheld, nil, [32]byte{}, at), 2)
			},
			2, ErrInvalid,
		},
		{
			"invalid finding",
			func(f *fixture, id DisputeID, ex ExchangeRef) Ruling {
				r := NewCreditRuling("cloudy", id, ex, Finding(0), HarmUpheld, nil, [32]byte{}, at)
				return f.signRuling(r, 2)
			},
			2, ErrInvalid,
		},
	}
	for _, tc := range neg {
		tc := tc
		t.Run("reject "+tc.name, func(t *testing.T) {
			f := newFixture(t, 2)
			ex := ref(0x22)
			f.anchors.seal(ex, f.cPub, f.rPub)
			id, err := f.reg.Open(mkOpening(t, f.cPub, f.cKey, f.rPub, ex))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			r := tc.make(f, id, ex)
			err = f.reg.Rule(r)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Rule(%s) = %v, want %v", tc.name, err, tc.wantErr)
			}
			// The case must remain open after a rejected ruling.
			c, _ := f.reg.Case(id)
			if c.State() != StateOpen {
				t.Fatalf("case state after rejected ruling = %v, want StateOpen", c.State())
			}
		})
	}
}

// TestOpen_RejectsReDisputeAfterRuling: a RESOLVED exchange is settled. A new
// Opening over the same (exchange, complainant, respondent) after a ruling must
// be rejected with ErrAdjudicated, so no second ruling — and thus no double
// refund/escalation — can occur over one exchange. (Re-dispute after a
// WITHDRAWAL stays admissible and is covered separately.)
func TestOpen_RejectsReDisputeAfterRuling(t *testing.T) {
	f := newFixture(t, 2)
	ex := ref(0x7C)
	f.anchors.seal(ex, f.cPub, f.rPub)
	at := time.Unix(1_700_000_000, 0).UTC()

	id, err := f.reg.Open(mkOpening(t, f.cPub, f.cKey, f.rPub, ex))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ruling := f.signRuling(NewCreditRuling("cloudy", id, ex, FindingForComplainant, HarmUpheld, nil, [32]byte{}, at), 2)
	if err := f.reg.Rule(ruling); err != nil {
		t.Fatalf("Rule: %v", err)
	}

	// A fresh opening over the SAME exchange+pair, with a distinct leaf ID (via a
	// later timestamp) so it clears the artifact-dedup check and actually reaches
	// the adjudicated guard rather than tripping ErrDuplicate first.
	o2, err := NewOpening("cloudy", f.cPub, f.rPub, ex, [32]byte{}, at.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	if err := o2.Sign(f.cKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := f.reg.Open(o2); !errors.Is(err, ErrAdjudicated) {
		t.Fatalf("re-Open after ruling = %v, want ErrAdjudicated", err)
	}
}
