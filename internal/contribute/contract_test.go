package contribute

import (
	"errors"
	"testing"
)

func TestWorkloadKindString(t *testing.T) {
	cases := map[WorkloadKind]string{
		Compute: "compute", Print: "print", Storage: "storage",
		Service: "service", WorkloadKind(99): "unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("WorkloadKind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
	if WorkloadKind(99).Valid() {
		t.Error("WorkloadKind(99) should be invalid")
	}
	for _, k := range []WorkloadKind{Compute, Print, Storage, Service} {
		if !k.Valid() {
			t.Errorf("%s should be valid", k)
		}
	}
}

func TestNodeContractValidate(t *testing.T) {
	cases := []struct {
		name string
		c    NodeContract
		want error
	}{
		{"empty", NodeContract{Placement: Pinned}, ErrNoKinds},
		{"invalid kind", NodeContract{Placement: Pinned, Kinds: []WorkloadKind{WorkloadKind(42)}}, nil}, // sentinel checked below
		{"duplicate", NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Compute, Compute}}, ErrDupKind},
		{"service scavenged", NodeContract{Placement: Scavenged, Kinds: []WorkloadKind{Service}}, ErrServiceNeedsPinned},
		{"service pinned ok", NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Service}}, nil},
		{"scavenged compute ok", NodeContract{Placement: Scavenged, Kinds: []WorkloadKind{Compute, Storage}}, nil},
		{"pinned mixed ok", NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Compute, Storage, Service}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if tc.name == "invalid kind" {
				if err == nil {
					t.Fatal("expected an error for an invalid kind")
				}
				return
			}
			if tc.want == nil && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNodeContractAllows(t *testing.T) {
	c := NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Compute, Storage}}
	if !c.Allows(Compute) || !c.Allows(Storage) {
		t.Error("contract should allow its own kinds")
	}
	if c.Allows(Service) || c.Allows(Print) {
		t.Error("contract should not allow uncontracted kinds")
	}
}
