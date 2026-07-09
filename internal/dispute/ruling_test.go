package dispute

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestRemedyValidateModeCoherence(t *testing.T) {
	esc := &Escalation{Action: ActionRefundComplainant, Units: 7}
	refund := &RefundDirective{Units: 7}

	cases := []struct {
		name   string
		mode   Mode
		remedy Remedy
		ok     bool
	}{
		{"escrow with escalation", ModeEscrow, Remedy{Escalation: esc}, true},
		{"escrow missing escalation", ModeEscrow, Remedy{}, false},
		{"escrow with bad action", ModeEscrow, Remedy{Escalation: &Escalation{Action: 0, Units: 1}}, false},
		{"escrow leaks harm field", ModeEscrow, Remedy{Escalation: esc, Harm: HarmUpheld}, false},
		{"escrow leaks refund field", ModeEscrow, Remedy{Escalation: esc, Refund: refund}, false},
		{"credit harm upheld", ModeCredit, Remedy{Harm: HarmUpheld}, true},
		{"credit harm expunged", ModeCredit, Remedy{Harm: HarmExpunged}, true},
		{"credit harm with refund", ModeCredit, Remedy{Harm: HarmUpheld, Refund: refund}, true},
		{"credit missing harm", ModeCredit, Remedy{}, false},
		{"credit leaks escalation", ModeCredit, Remedy{Harm: HarmUpheld, Escalation: esc}, false},
		{"unknown mode", Mode(0), Remedy{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.remedy.validate(tc.mode)
			if tc.ok && err != nil {
				t.Fatalf("validate(%v) = %v, want nil", tc.mode, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("validate(%v) = nil, want an error", tc.mode)
			}
		})
	}
}

func TestConstructorsProduceCoherentRulings(t *testing.T) {
	dispID := DisputeID{1: 1}
	ex := ref(0xA1)
	at := time.Unix(1_700_000_000, 0).UTC()

	esc := NewEscrowRuling("cloudy", dispID, ex, FindingForComplainant, ActionRefundComplainant, 42, [32]byte{}, at)
	if esc.Mode != ModeEscrow {
		t.Fatalf("NewEscrowRuling mode = %v, want ModeEscrow", esc.Mode)
	}
	if err := esc.Remedy.validate(esc.Mode); err != nil {
		t.Fatalf("NewEscrowRuling produced an incoherent remedy: %v", err)
	}
	if esc.Remedy.Escalation == nil || esc.Remedy.Escalation.Units != 42 {
		t.Fatal("NewEscrowRuling did not carry the escalation directive")
	}

	cr := NewCreditRuling("cloudy", dispID, ex, FindingForComplainant, HarmExpunged, &RefundDirective{Units: 5}, [32]byte{}, at)
	if cr.Mode != ModeCredit {
		t.Fatalf("NewCreditRuling mode = %v, want ModeCredit", cr.Mode)
	}
	if err := cr.Remedy.validate(cr.Mode); err != nil {
		t.Fatalf("NewCreditRuling produced an incoherent remedy: %v", err)
	}
	if cr.Remedy.Harm != HarmExpunged || cr.Remedy.Refund == nil || cr.Remedy.Refund.Units != 5 {
		t.Fatal("NewCreditRuling did not carry the harm disposition and refund")
	}
}

func TestRulingVerifyThreshold(t *testing.T) {
	a1Pub, a1 := genKeyT(t)
	a2Pub, a2 := genKeyT(t)
	a3Pub, a3 := genKeyT(t)
	_, stranger := genKeyT(t)

	charter := Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{a1Pub, a2Pub}, Threshold: 2}

	base := func() Ruling {
		return NewEscrowRuling("cloudy", DisputeID{1: 1}, ref(0xA1), FindingForComplainant, ActionRefundComplainant, 1, [32]byte{}, time.Unix(1, 0).UTC())
	}

	t.Run("no sigs", func(t *testing.T) {
		if base().Verify(charter) {
			t.Fatal("unsigned ruling must not verify")
		}
	})
	t.Run("one sig below threshold", func(t *testing.T) {
		r := base()
		r.Sign(a1)
		if r.Verify(charter) {
			t.Fatal("one sig must not satisfy threshold 2")
		}
	})
	t.Run("two distinct authorized sigs", func(t *testing.T) {
		r := base()
		r.Sign(a1)
		r.Sign(a2)
		if !r.Verify(charter) {
			t.Fatal("two distinct authorized sigs must satisfy threshold 2")
		}
	})
	t.Run("duplicate signer counts once", func(t *testing.T) {
		r := base()
		r.Sign(a1)
		r.Sign(a1)
		if r.Verify(charter) {
			t.Fatal("the same adjudicator signing twice must count once")
		}
	})
	t.Run("non-roster signer counts nothing", func(t *testing.T) {
		r := base()
		r.Sign(a1)
		r.Sign(stranger)
		if r.Verify(charter) {
			t.Fatal("a non-roster signature must not count toward threshold")
		}
	})
	t.Run("extra roster member ok", func(t *testing.T) {
		c3 := Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{a1Pub, a2Pub, a3Pub}, Threshold: 2}
		r := base()
		r.Sign(a2)
		r.Sign(a3)
		if !r.Verify(c3) {
			t.Fatal("any two distinct roster members must satisfy threshold 2")
		}
	})
}

func TestRulingSignatureBindsCanonicalBytes(t *testing.T) {
	aPub, aKey := genKeyT(t)
	charter := Charter{Platform: "cloudy", Adjudicators: []ed25519.PublicKey{aPub}, Threshold: 1}
	r := NewEscrowRuling("cloudy", DisputeID{1: 1}, ref(0xA1), FindingForComplainant, ActionRefundComplainant, 1, [32]byte{}, time.Unix(1, 0).UTC())
	r.Sign(aKey)
	if !r.Verify(charter) {
		t.Fatal("signed ruling must verify")
	}
	// Change a remedy field after signing: the signature must no longer verify.
	r.Remedy.Escalation.Units = 999
	if r.Verify(charter) {
		t.Fatal("mutating the escalation units after signing must invalidate the signature")
	}
}
