// Package dispute implements Cloudy's member-facing dispute domain: how a
// member formally contests a sealed exchange, how a generic staff panel rules
// on it, and how the outcome is realized WITHOUT violating any invariant of
// the layers it sits beside. This is a JFA member-economy layer the substrate
// coordination protocol deliberately does not define, and it is Cloudy's to
// own.
//
// # Where it sits in the JFA layering
//
// dispute is a FOURTH JFA dependency leaf, built exactly like record, economy,
// and covenant: it imports the standard library and
// sohocloud-protocol/canon ONLY, imports none of its sibling layers, and
// touches other layers exclusively through opaque [32]byte values and port
// interfaces (Anchors, Store) resolved at the composition root (cmd/cloudy,
// test/composition). It mirrors covenant's three-part shape: signed message
// types (CanonicalBytes / Sign / Verify / ID), a stateful admission object
// (Registry) with a Store port and a Charter config, and a replay-derived read
// model (Case). No organization or company name appears anywhere — the
// deciding role is the generic Charter.Adjudicators staff roster.
//
// # The artifacts and the state machine
//
// Three signed artifacts drive one case:
//
//   - Opening: a complainant-authored, complainant-signed assertion against a
//     respondent, grounded in one disputed exchange. Its ID() is the case's
//     identity, the DisputeID.
//   - Ruling: a staff-authored, mode-aware decision carrying a threshold of
//     distinct adjudicator signatures verified against the Charter (mirrors
//     economy.PolicyChange's quorum).
//   - Withdrawal: a complainant-signed retraction of an open case.
//
// The machine has one non-terminal and two terminal states:
//
//	(none) --Opening--> Open --Ruling--> Resolved (terminal)
//	                    Open --Withdrawal--> Withdrawn (terminal)
//
// Only an Open case accepts a Ruling or Withdrawal (ErrClosed otherwise).
// There is at most one live (non-terminal) dispute per (exchange, complainant,
// respondent); a genuine re-dispute after a terminal state is a NEW Opening
// with a fresh nonce, hence a new DisputeID. Case state is always REPLAYED
// from the ordered Store artifacts, never read from a stored scalar — the same
// LBTAS-derived discipline as record.OpenLog and economy.Open.
//
// # Commons-safety and the no-PII discipline
//
// Every artifact is commons-safe by construction: fixed-size hashes, ed25519
// keys, enums, a random nonce, and a UTC instant. The only member-authored
// narrative — an Opening's reason and a Ruling's rationale — lives member-local
// in the record layer's erasable Locker; the commons carries only ReasonHash
// and RationaleHash (32 opaque bytes each, mirroring covenant.CommentHash). If
// the composition seam ever wrote that text into a record or commons field it
// would breach the no-PII-in-commons invariant.
//
// # Mode-aware resolution — the heart of the package
//
// A Ruling's Mode (a dispute-local type DISTINCT from economy.Mode) is supplied
// by the caller — the seam maps the ledger's policy — and dispute never infers
// economy state. The two resolution paths respect the neighbouring layers'
// invariants exactly:
//
//   - ModeEscrow -> escalate, move no money. Cloudy structurally cannot move
//     escrowed fiat (economy has no mint or clawback; fiat sits at the
//     coordinator), so the remedy is a staff-SIGNED DIRECTIVE to the
//     coordinator: an Escalation with a CoordinatorAction and an OPAQUE
//     uint64 Units the coordinator maps to fiat. The signed Ruling IS the
//     escalation record; the seam ships it to the coordinator via coord.Client.
//     Units is deliberately a bare uint64, never an economy.Amount or a fiat
//     type, so no fiat reference leaks into the JFA layers.
//
//   - ModeCredit -> reputational overlay plus voluntary refund, never forced
//     clawback. A Ruling carries a HarmDisposition (uphold or expunge the harm
//     flag) and, optionally, a RefundDirective. Two hard constraints:
//
//     Covenant is immutable — there is NO retraction API, and an admitted
//     No Trust (-1) is permanent (covenant.Standing.Harm keeps counting it).
//     "Expunge" is therefore NOT a covenant deletion; it is an adjudicated
//     overlay recorded in the dispute/record trail. Any reputation
//     presentation must COMPOSE covenant standing with dispute rulings —
//     reading covenant.Standing alone will still see the harm.
//
//     Forced clawback is impossible by economy invariant. A directed refund is
//     a NEW payee-signed economy.Spend (original payee -> original payer) that
//     the seam constructs as an UNSIGNED template; the payee signs it
//     voluntarily. dispute emits only the directive — it can never sign or
//     force the transfer. If the payee refuses, credit-mode has no financial
//     remedy beyond the reputational overlay. This is by design, not a bug.
//
// # The cross-layer gate
//
// dispute deliberately leaves ExchangeRef unchecked internally, exactly as
// economy leaves Spend.ExchangeHash unchecked. The load-bearing check lives at
// the composition root: the Anchors predicate resolves the disputed entry in
// the operator's record log and confirms its parties equal the complainant and
// respondent, bound to that log. Without the seam wiring that gate on Open, a
// dispute could be opened over a nonexistent exchange or by a non-party.
//
// # Tamper-evidence via the record layer
//
// The seam mirrors each admitted artifact into the operator's record.Log as a
// new dialog-sealed Entry whose Content is record.HashContent of the artifact's
// canonical bytes (the bytes held in a member-local Locker). record.Entry
// demands two DISTINCT member seals and refuses a half-sealed entry, while a
// dispute Opening is one-sided and a Ruling is staff-imposed; the reconciliation
// is a party pairing that avoids a disputant liveness hole: an Opening is
// sealed complainant + intake staff (acknowledgment of receipt, NOT consent),
// and a Ruling is sealed by two panel adjudicators (four-eyes) — which is why
// recording rulings into the record wants Charter.Threshold >= 2. A
// single-adjudicator deployment cannot dialog-seal rulings into the record and
// relies on dispute's own append-only Store (or the coordinator) for
// tamper-evidence.
//
// # Canonical bytes and domain tags
//
// Each artifact's canonical signing payload begins with its own domain tag
// (cloudy/dispute/opening/v0, .../ruling/v0, .../withdrawal/v0), and artifact
// leaf IDs derive under cloudy/dispute/id/v0 over the canonical bytes plus the
// signature(s), like record.Entry.ID(). v0 is unstable — the layout may change
// without compatibility guarantees.
package dispute
