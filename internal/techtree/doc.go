// Package techtree is Cloudy's knowledge substrate: the claim + citation graph
// behind the JFA Economy & Education layer's "empirical claims & citizen
// science" surface (Building JFA v2, Part III, surface #3). It is the shared
// substrate the marketplace also rides — a product spec is a techtree claim of
// Kind product_spec (surface #1), so a buyer's exchange can cite or contest the
// specs a maker advertises, and reputation cannot be advertised into existence.
//
// What it is. A member anchors a CLAIM as a claim — its inputs, method, and
// result — and members draw typed REFERENCES between claims (cites, builds_on,
// contests, reproduces, refutes). Nodes are claims; edges are references; the
// whole is a citation graph presented as a "technology tree" of accreting,
// contestable knowledge. Claims and references accumulate in an append-only,
// hash-chained log fully re-verified on Open — the same discipline as
// internal/record.
//
// The invariants it is held to (Building JFA v2, Part III):
//
//   - NO TRUTH AUTHORITY. The network never certifies a claim true. There is
//     no Verified/Certified/Official flag anywhere and there is deliberately
//     no scoring, ranking, or "what's best" function — a single index of truth
//     would be a hosting chokepoint wearing a scholar's gown. A claim is made
//     auditable and citable; whether it holds up is surfaced by contestable
//     citation and by the covenant's rating of the CLAIMANT, never decreed.
//     Two tripwire tests keep this true (see techtree_test.go).
//   - A CONTEST IS A NEW CLAIM, NEVER AN ERASURE. To dispute claim X you author
//     your own claim Y (with its own inputs/method/result) and draw a
//     RefContests edge Y→X. The log is append-only; nothing is deleted or
//     edited (record invariant).
//   - NO PII IN THE COMMONS. A claim's field set is closed — no free-text field
//     exists. The inputs/method/result narratives live member-local (the
//     Locker); the commons carries only their SHA-256 hashes plus structural
//     facts (kind, claimant key, timestamps), mirroring dispute.Opening's
//     ReasonHash and record.Entry's Content.
//   - PER-PLATFORM, NON-PORTABLE. Every claim and reference binds a Platform
//     string into its signed bytes, so an artifact is non-transferable across
//     platforms by construction (covenant invariant).
//   - TWO DISTINCT TRUST SIGNALS, NOT CONFLATED. (1) Claimant standing lives in
//     the covenant (LBTAS), out of this package — techtree exposes the claimant
//     key so the composition root can rate them; it never rates anyone itself.
//     (2) Citation weight (weight.go) is a LEGIBLE, FORKABLE breakdown by edge
//     kind and distinct asserter — never averaged into a score.
//
// LABELED STAND-INS (house discipline — name the gap):
//   - Citation weight counts DISTINCT asserter keys as a weak Sybil mitigation,
//     but distinct-key is NOT Sybil-resistance. Per Part III, citation weight
//     MUST size zero economic reward until the identity/Sybil approach (open
//     problem 4) is settled — exactly as member credit is gated. It is legible
//     and informational only; nothing here pays or ranks-for-sale on it.
//   - The log is append-only and hash-chained but not yet witnessed. Cloudy's
//     record witnessing (checkpoints + independent witnesses) is the shared
//     follow-up; until then this is a single-writer StandIn, labeled as one.
//
// This package imports only the protocol's canon and the standard library — no
// other JFA layer — so the composition root wires it to the covenant and record
// exactly as it wires economy/covenant/record/dispute.
package techtree
