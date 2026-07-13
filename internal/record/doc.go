// Package record is Drops — Cloudy's dialog-sealed, append-only, witnessed
// record: the durable account of what two members agreed to, kept as
// per-operator hash-chained logs whose integrity any member can verify
// offline. Drops is the product name (and the domain-tag namespace, drops/*);
// record stays the Go package name per the 2026-07-09 naming decision. It is a
// JFA member-economy layer the substrate coordination protocol does not
// define, and the member-facing analogue of the protocol's anchor/ package:
// anchor/ reserves witnessing of substrate EMPLOYMENT claims; this package
// witnesses member COVENANT within Cloudy. Both inherit the same no-PII,
// append-only, no-global-ledger invariants, and both follow the Certificate
// Transparency factoring — the operator commits, independent witnesses
// countersign after the fact, and members verify everything themselves.
//
// # The cross-layer exchange reference
//
// Entry.ID() — the entry's leaf hash — is THE cross-layer exchange
// reference. When any other JFA layer (economy, covenant) carries an opaque
// [32]byte reference to a sealed exchange, that value is the record entry's
// leaf ID: exactly Entry.ID() of the fully sealed entry. The Content hash is
// NOT that reference — it digests erasable, member-local narrative bytes and
// is not unique to a sealed covenant, while the nonce-bearing leaf ID is.
// Other layers hold the leaf ID strictly by value, never by importing this
// package's types; conversion between the layers' [32]byte types happens
// only at the composition root.
//
// # Invariants and the mechanisms that enforce them
//
// The commons MUST NOT contain PII; the witnessed, shared record holds
// references and hashes only. Structural: every commons type (Entry,
// Checkpoint, Countersignature, Proof, WitnessedCheckpoint) is composed
// solely of fixed-size hashes, ed25519 keys, a uint64, a random nonce, a UTC
// instant, and ed25519 signatures — no string field exists, and while the
// seal, signature, and key fields are []byte slices in Go, every Verify pins
// each to its fixed ed25519 length (a runtime rung, not a structural one),
// so no open-ended metadata or memo PII channel survives verification. Members
// appear only as bare public keys; LogID is derived from a key, never chosen
// text, so it cannot be squatted and cannot carry a name. Content bytes
// enter the package through exactly two doors — HashContent, which consumes
// them into a digest and retains nothing, and Locker, which never touches a
// log — and no marshaling, export, or backup API exists to smuggle content
// into a portable format.
//
// Any identifying content stays in ERASABLE, member-local storage, never in
// the commons. Structural: Locker is the member-local half of the record and
// is type-disjoint from Store and Log — it speaks []byte and Hash, never
// Entry — so storing content in a log is a type error, not a code-review
// catch. Erase exists on exactly one type in the package, and it is the type
// that never enters a chain; erasing content leaves every previously issued
// inclusion proof fully verifiable, so the commons never notices erasure.
//
// The record is append-only and witnessed. Entries are added, never edited
// or deleted; corrections are new entries. Structural first: Store's whole
// interface is Append/At/Len and Log's sole mutating method is Append —
// update and delete are absent verbs, not forbidden ones — and a correction
// is an ordinary new Entry whose Corrects field references the entry it
// corrects while removing nothing. Runtime second: OpenLog replays and
// cryptographically re-verifies the entire store (seals, log binding,
// corrections, duplicates, chain fold), rejecting invalid, foreign,
// duplicate, and dangling-correction entries — but the ORDER of independent
// un-checkpointed entries is NOT fixed by replay alone: a store with two
// such entries swapped replays cleanly to a different head. That order is
// protected by the next rung, and the gap is exactly CT's residual. Append
// rejects a nonzero Corrects that names no in-log entry. Detectable third:
// operator-signed monotonic Checkpoints plus
// VerifyConsistency make any rewrite of checkpointed history
// cryptographically visible to anyone holding an older checkpoint; the
// checkpoint pair is itself portable fork evidence.
//
// The record MUST NOT be a single global ledger over unrelated exchanges.
// Structural: a Log is constructed from exactly one operator key, and its
// derived identity LogID(operator) seeds the chain fold, so every position
// is scoped to one log. Each Entry carries its LogID INSIDE the dual-signed
// bytes, so a sealed covenant can never migrate or be replayed into another
// operator's log, and Checkpoint.Verify binds cp.Log == LogID(operator) so
// commitments cannot be replayed either. The package exports no merge, no
// cross-log query, no global ordering, and no registry — a global ledger
// cannot be assembled from this surface.
//
// The record MUST NOT require a central authority or a consensus layer;
// witnesses are independent and federatable (the CT model reserved in the
// protocol's anchor/ package). Log.Append takes no witness parameter — a
// witness structurally cannot approve, veto, or author entries; its role is
// retrospective countersigning of published checkpoints, so refusal cannot
// censor. No quorum type, vote, leader, or arbiter exists anywhere in the
// surface; federation is literally appending another Countersignature to a
// WitnessedCheckpoint, whose Verify enforces independence: pairwise-distinct
// witness keys, none equal to the operator's. Witness keys are resolved and
// trusted out-of-band; the package distributes no keys.
//
// A single-witness deployment MUST be labeled the stand-in it is, with a
// path to independent witnesses. WitnessedCheckpoint.StandIn(operator)
// reports fewer than two verified, operator-independent witness
// cosignatures — unverifiable or operator-authored cosignatures do not
// count — so any surface presenting a checkpoint has the label in hand
// without also calling Verify; the path to federation is structural —
// independent witnesses join by appending countersignatures, no protocol
// change required. How many witnesses run at launch remains the governance
// call anchor/ says it is; this API only forbids misrepresenting one witness
// as federation.
//
// The record is dialog-sealed: an entry records what two members agreed to,
// not what one party asserts. Entry.Verify demands two DISTINCT well-formed
// member keys and valid seals from BOTH over the same canonical bytes; Seal
// can only fill the slot matching the signing key; NewEntry rejects
// self-dialog at construction; and Log.Append refuses anything that does not
// fully Verify — a half-sealed or self-dealt entry can never enter any log.
// The operator holds no key that can produce a member seal, so its entire
// power is assigning sequence numbers: it can order covenants but never
// author, amend, or remove one. The random nonce keeps textually identical
// agreements distinct and makes double-appends detectable.
//
// Signing bytes are canonical, domain-separated, and UTC. All signing and
// hashing payloads are built with the protocol's canon package under the six
// distinct tags below; canon.Time normalizes every signed instant to UTC
// nanoseconds and drops monotonic and location components.
//
// # Domain tags
//
// Every hash and signature in the package is computed over canonical bytes
// beginning with one of six distinct, unexported domain tags:
//
//	drops/content/v0     HashContent digests
//	drops/entry/v0       Entry signing payloads (both seals)
//	drops/leaf/v0        Entry.ID leaf hashes
//	drops/chain/v0       the chain derivation: LogID seed and fold steps
//	drops/checkpoint/v0  Checkpoint signing payloads
//	drops/witness/v0     witness countersignature payloads
//
// so no artifact is transferable between message types, between a hash role
// and a signature role, or back into sohocloud-protocol messages. The chain
// tag covers the two arities of the one chain derivation — the single-field
// seed (LogID over the operator key) and the two-field fold step — which
// canon's length prefixes keep disjoint.
//
// # Named residuals
//
// Steganographic floor: a 32-byte hash field can physically carry 32
// arbitrary bytes. A party determined to encode data where a digest belongs
// can do so; that floor is irreducible in any hash-referencing design and is
// named here rather than pretended away. It admits no plaintext narrative,
// no key-value channel, and nothing beyond 32 bytes per field.
//
// Timestamp covert channel: SealedAt is a UTC nanosecond instant inside the
// dual-signed bytes, and its low-order digits are chooseable by the sealing
// parties — a nanosecond instant can carry tens of bits of arbitrary data
// into the commons per entry. Like the steganographic floor it admits no
// plaintext narrative and is named rather than pretended away.
//
// Witness amnesia: a Witness's rollback/fork memory (the last checkpoint it
// cosigned per log) lives only in the process; a reconstructed Witness
// reverts to trust-on-first-checkpoint and will cosign a rewritten head it
// would previously have refused. A deployment MUST run each witness as a
// single long-lived value and treat durability of its state as a deployment
// concern. The mitigation that bounds the damage: older cosigned
// checkpoints remain portable fork evidence regardless, so a post-amnesia
// rewrite is still cryptographically visible to anyone holding an earlier
// WitnessedCheckpoint.
//
// Liveness: an operator can refuse to append, and non-inclusion cannot be
// proven — exactly CT's liveness gap. The member's remedy is structural:
// both parties hold the completed, dual-sealed Entry, and a member who holds
// it can demand an inclusion proof against any later checkpoint; an operator
// that stonewalls is accountable to evidence it cannot forge or erase.
package record
