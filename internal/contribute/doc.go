// Package contribute is the contributor-node Executor seam: the interface a
// Cloudy member machine implements to contribute capacity, decoupled from any
// one runtime. Docker containers, an Android storage provider, a long-running
// service, and GPU compute are all Executors behind this seam; none of them is
// the definition. The seam exists so the runtime-heavy implementations
// (docker/gopsutil/spiffe) plug into a contract that is already fixed and
// tested, rather than the contract being whatever today's Docker code happens
// to do.
//
// This package is NOT a JFA member-economy leaf. It never imports
// economy/covenant/record/dispute, and nothing in the import graph makes it a
// composition root. It is the node/contribution plane, which is a different
// concern from the member's credit/covenant/record world.
//
// Invariants this seam defends:
//
//   - Owner is never interrupted. A node offered on SCAVENGED (idle-first)
//     capacity may only host PREEMPTIBLE executors — work that can be paused or
//     stopped the moment the owner returns. The Registry refuses to register a
//     non-preemptible executor on a scavenged contract, and the agent control
//     loop stops advertising and dispatching scavenged work while the owner is
//     active.
//
//   - A service is pinned, not scavenged. A long-running service cannot yield
//     to the owner at 2pm, so it requires declared, dedicated (PINNED)
//     capacity. NodeContract.Validate rejects a Service workload on a scavenged
//     node; that is the structural line between "lend my idle desktop" and
//     "dedicate this box to running a thing".
//
//   - Opt-out is enforced locally, never trusted from the wire. Capabilities()
//     advertises only what the node's own contract permits; the advertisement
//     is a hint to the matcher, and the executor still refuses out-of-contract
//     work locally. The coordinator is not a security boundary for opt-out.
//
// The seam carries no bytes of member data and speaks no protocol: it is the
// local dispatch contract. Wire relaying (agent signs node messages, cloudyd
// relays them over SCP /v0) sits above this package, per the Phase-1 design.
package contribute
