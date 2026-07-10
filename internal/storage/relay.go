package storage

import "context"

// Relay is countermeasure 3 as an architectural boundary: the ONLY doorway
// through which member-side code moves shard bytes. Its production
// implementation lives in cloudyd (the platform relays between member and
// host), mirroring the accepted control-plane pattern — the agent signs,
// cloudyd relays. A host therefore observes the platform's address on every
// transfer and never a member's.
//
// Member-side code MUST NOT dial a host directly; there is deliberately no
// host-addressed API anywhere in this package, so the compiler enforces
// what the design promises. TestNoNetworkImport (nonetwork_test.go) asserts
// this package's non-test import graph pulls in no networking package (net,
// net/http, …), so a future host-dialing addition fails the build.
//
// The wire that carries these calls is data plane — outside sohocloud-
// protocol by its §1 scope rule ("the wire never carries stored content").
// The relay transport (cloudyd HTTP, Phase 2) authenticates the member on
// one side and the node's SPIFFE identity on the other; neither party
// learns the other's network location.
type Relay interface {
	// Put stores a sealed shard with the host currently assigned ref.
	Put(ctx context.Context, ref [32]byte, sealed []byte) error
	// Get retrieves a sealed shard by ref.
	Get(ctx context.Context, ref [32]byte) ([]byte, error)
	// Probe forwards a proof-of-storage challenge and returns the host's
	// response digest. Reads that ride a probe slot (see cover.go) and real
	// audits cross this same method, so the two are indistinguishable to
	// the transport as well as in timing.
	Probe(ctx context.Context, ref [32]byte, ch Challenge) ([32]byte, error)
}
