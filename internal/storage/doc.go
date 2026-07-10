// Package storage is Cloudy's member-side storage privacy layer: the code
// that guarantees a host storing a member's data can neither read it nor
// learn much from watching it move. It implements the four traffic-shape
// countermeasures agreed 2026-07-09 (PHASE1 design §5b) on top of the §5a
// encryption pipeline, entirely ABOVE the sohocloud-protocol thin waist —
// nothing in this package touches the wire, and the wire never carries
// stored content.
//
// The pipeline (§5a): an object is framed and padded to a quantized size
// class, split into shards by a pluggable erasure Coder, and each shard is
// sealed with AES-256-GCM under a random per-object key with its position
// bound as AAD. A host receives only a sealed shard and its content address;
// the member's manifest (object → key → shard refs → challenge table) lives
// in the member-local Locker, never in the commons.
//
// The four countermeasures (§5b):
//
//  1. Size quantization (quantize.go, object.go) — every sealed shard in a
//     size class has an identical byte length, so shard size fingerprints
//     nothing. Enforced by construction and by test.
//  2. Placement and fetch decorrelation (placement.go, fetch.go) — no single
//     host ever holds two shards of one object (a HARD rule, enforced
//     fail-closed), and retrieval order and timing are randomized, so no one
//     host can regroup an object. Distinct owners are PREFERRED but not
//     guaranteed: when distinct owners are scarcer than the shard count, a
//     multi-node owner can still co-observe several shards of one object
//     across its own hosts — the guarantee is "no single host regroups," not
//     "no operator correlates."
//  3. Relay boundary (relay.go) — member-side code never dials a host; all
//     shard traffic crosses the Relay interface implemented by cloudyd, so
//     a host sees the platform's address, never the member's.
//  4. Audits as cover traffic (audit.go, cover.go) — proof-of-storage
//     challenges fire on a randomized steady cadence whether or not anyone
//     is reading, and latency-tolerant reads ride probe slots, so within the
//     cadence a host cannot distinguish interest from routine. The cadence is
//     exponential but clamped (see cover.go), so it is near-memoryless rather
//     than strictly memoryless; a read that cannot wait for the next slot
//     steps outside it (a named residual leak below).
//
// Labeled stand-ins, per house discipline (name the gap, don't paper over
// it): StandInSplitter provides NO redundancy (Reed-Solomon k-of-n is the
// named follow-up), and the challenge table is a finite-budget
// proof-of-storage (homomorphic-tag PoR is the named follow-up). The wire
// messages that will carry challenges and lease terms are SCP v0.3 scope —
// see Development/SCP-completion-roadmap.md.
//
// Residual leaks, named honestly: shard traffic volume per host is still
// observable (bounded by class sizes); urgent reads that cannot wait for a
// probe slot step outside the cover cadence; a global network observer or a
// colluding majority of hosts remains out of scope for Phases 1–3.
package storage
