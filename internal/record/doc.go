// Package record is a STUB. It is not built.
//
// It reserves the place for Cloudy's dialog-sealed record: the durable,
// witnessed account of what members agreed to. This is a JFA member-economy
// layer the substrate coordination protocol does not define.
//
// When it is built, these Janus-Facing Architecture invariants are NOT
// negotiable:
//
//   - The commons MUST NOT contain PII. The witnessed, shared record holds
//     references and hashes; any identifying content stays in erasable,
//     member-local storage, never in the commons.
//   - The record is append-only and witnessed. Entries are added, never edited
//     or deleted; corrections are new entries. It MUST NOT be a single global
//     ledger over unrelated exchanges, and MUST NOT require a central authority
//     or a consensus layer — per-operator logs with independent, federatable
//     witnesses (the model reserved in the protocol's anchor/ package).
//
// This is the member-facing analogue of the protocol's anchor/ stub: anchor/
// concerns witnessing substrate EMPLOYMENT claims; this concerns witnessing
// member COVENANT within Cloudy. Both are unbuilt and both inherit the same
// no-PII, append-only, no-global-ledger invariants.
package record
