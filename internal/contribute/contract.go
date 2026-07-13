package contribute

import (
	"errors"
	"fmt"
)

var (
	// ErrNoKinds means a contract advertises no workload kinds.
	ErrNoKinds = errors.New("contribute: node contract advertises no workload kinds")
	// ErrServiceNeedsPinned means a Service kind was contracted on scavenged
	// capacity — forbidden, because a service cannot yield to the owner.
	ErrServiceNeedsPinned = errors.New("contribute: service workload requires pinned placement")
	// ErrDupKind means a workload kind appears twice in a contract.
	ErrDupKind = errors.New("contribute: duplicate workload kind in contract")
)

// NodeContract is the owner's standing declaration: which workload kinds this
// machine accepts and on what terms (scavenged vs pinned). It is the local
// source of truth the Registry and agent enforce against; the wire never
// widens it.
type NodeContract struct {
	NodeID    string
	Placement Placement
	Kinds     []WorkloadKind
}

// Validate enforces the contract's internal invariants: at least one kind, no
// duplicates, all valid, and — the load-bearing rule — no Service on scavenged
// capacity.
func (c NodeContract) Validate() error {
	if len(c.Kinds) == 0 {
		return ErrNoKinds
	}
	seen := make(map[WorkloadKind]bool, len(c.Kinds))
	for _, k := range c.Kinds {
		if !k.Valid() {
			return fmt.Errorf("contribute: invalid workload kind %d", int(k))
		}
		if seen[k] {
			return fmt.Errorf("%w: %s", ErrDupKind, k)
		}
		seen[k] = true
	}
	if seen[Service] && c.Placement != Pinned {
		return ErrServiceNeedsPinned
	}
	return nil
}

// Allows reports whether k is within this contract.
func (c NodeContract) Allows(k WorkloadKind) bool {
	for _, x := range c.Kinds {
		if x == k {
			return true
		}
	}
	return false
}
