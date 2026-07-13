package dispute

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestNewOpeningRejectsMalformed(t *testing.T) {
	cPub, _ := genKeyT(t)
	rPub, _ := genKeyT(t)
	ex := ref(0xA1)
	at := time.Unix(1_700_000_000, 0).UTC()

	cases := []struct {
		name                    string
		complainant, respondent ed25519.PublicKey
		exchange                ExchangeRef
	}{
		{"short complainant", cPub[:10], rPub, ex},
		{"short respondent", cPub, rPub[:10], ex},
		{"equal parties", cPub, cPub, ex},
		{"zero exchange", cPub, rPub, ExchangeRef{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewOpening("cloudy", tc.complainant, tc.respondent, tc.exchange, [32]byte{}, at); err == nil {
				t.Fatalf("NewOpening(%s) = nil error, want rejection", tc.name)
			}
		})
	}
}

func TestNewOpeningDrawsDistinctNonces(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	ex := ref(0xA1)
	at := time.Unix(1_700_000_000, 0).UTC()
	o1, err := NewOpening("cloudy", cPub, rPub, ex, [32]byte{}, at)
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	o2, err := NewOpening("cloudy", cPub, rPub, ex, [32]byte{}, at)
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	if o1.Nonce == o2.Nonce {
		t.Fatal("two openings drew the same nonce; identical grievances must be distinguishable")
	}
	// Distinct nonces must yield distinct case IDs even with otherwise identical inputs.
	if err := o1.Sign(cKey); err != nil {
		t.Fatalf("Sign o1: %v", err)
	}
	if err := o2.Sign(cKey); err != nil {
		t.Fatalf("Sign o2: %v", err)
	}
	if o1.ID() == o2.ID() {
		t.Fatal("distinct nonces must yield distinct DisputeIDs")
	}
}

func TestOpeningSignVerify(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	o, err := NewOpening("cloudy", cPub, rPub, ref(0xA1), [32]byte{7: 9}, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	if o.Verify() {
		t.Fatal("unsigned opening must not verify")
	}
	if err := o.Sign(cKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !o.Verify() {
		t.Fatal("signed opening must verify")
	}
	// Tamper with a signed field: verification must fail.
	tampered := o
	tampered.Exchange = ref(0xFF)
	if tampered.Verify() {
		t.Fatal("tampered opening (exchange changed after signing) must not verify")
	}
}

func TestOpeningSignRejectsNonComplainant(t *testing.T) {
	cPub, _ := genKeyT(t)
	rPub, rKey := genKeyT(t)
	o, err := NewOpening("cloudy", cPub, rPub, ref(0xA1), [32]byte{}, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	// The respondent must not be able to sign the opening in the complainant's name.
	if err := o.Sign(rKey); err == nil {
		t.Fatal("Sign by a non-complainant must return an error")
	}
	if o.Signature != nil {
		t.Fatal("a rejected Sign must not leave a signature behind")
	}
}

func TestOpeningIDStableAndSignatureBound(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	o, err := NewOpening("cloudy", cPub, rPub, ref(0xA1), [32]byte{}, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	if err := o.Sign(cKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	id1 := o.ID()
	id2 := o.ID()
	if id1 != id2 {
		t.Fatal("ID must be stable across calls")
	}
	if id1 == (DisputeID{}) {
		t.Fatal("ID must not be the zero value for a signed opening")
	}
}

func TestOpeningCloneIsDeep(t *testing.T) {
	cPub, cKey := genKeyT(t)
	rPub, _ := genKeyT(t)
	o, err := NewOpening("cloudy", cPub, rPub, ref(0xA1), [32]byte{}, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("NewOpening: %v", err)
	}
	if err := o.Sign(cKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cp := o.clone()
	cp.Complainant[0] ^= 0xFF
	cp.Signature[0] ^= 0xFF
	if bytes.Equal(cp.Complainant, o.Complainant) {
		t.Fatal("clone shares the complainant key backing array")
	}
	if bytes.Equal(cp.Signature, o.Signature) {
		t.Fatal("clone shares the signature backing array")
	}
}
