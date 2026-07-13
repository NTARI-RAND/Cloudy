// Package economy implements Cloudy's member economy: member-issued credit
// within the Cloudy platform, realized as a per-platform mutual-credit ledger.
// This is a JFA member-economy layer that the substrate coordination protocol
// deliberately does not define, and it is Cloudy's to own.
//
// # The mutual-credit thesis
//
// "Member-issued" means issued at the moment of spending. Credit exists only
// as a payer's negative balance, created when a payer-signed Spend drives that
// payer below zero within one uniform, governed debit cap. Post debits the
// payer and credits the payee equally, so the system-wide sum of balances is
// always exactly zero: there is no pool, no treasury, and nothing accumulated
// that could ever be cashed out. A negative balance is a claim on the member's
// future contribution to the network; a positive balance is a claim on the
// network's goods and services — never on anything outside it.
//
// # Invariants (NOT negotiable)
//
//   - Credit is member-ISSUED, not sold. It MUST NOT be purchasable for fiat
//     and MUST NOT be redeemable back into fiat. It is spend-only within the
//     platform: a claim on the network's goods and services, not a security or
//     a store of external value. Enforced structurally: the package's only
//     credit-moving operation is Ledger.Post of a payer-signed Spend; purchase
//     and redemption are absent APIs, not forbidden ones, and no fiat amount,
//     currency code, or payment reference is representable in any type.
//   - Currency is per-platform and SOVEREIGN. There is no cross-platform unit
//     of account; Cloudy credit is denominated in Cloudy's own unit and MUST
//     NOT be made fungible with another platform's currency. Enforced
//     cryptographically: the platform string sits inside every domain-tagged
//     canonical payload and inside AccountID derivation, so a record signed
//     for another platform's ledger never verifies here, and the same member
//     key yields non-correlatable account IDs on different platforms. Platform
//     identity is fixed in Genesis — deliberately NOT part of the mutable
//     Policy — so sovereignty is never one Enact away from reconfiguration.
//   - Escrow-now, credit-later is a single policy switch, not two code paths.
//     A platform may start in fiat-escrow mode and later enable member credit;
//     that transition MUST be one governed configuration change, not a
//     rewrite. Enforced by type: Policy.Mode gates only Post's admission
//     (ModeEscrow returns ErrCreditDisabled; ModeCredit admits within the
//     debit cap), while Enact, Balance, Open, the record shapes, and the
//     domain tags are one shared code path identical in both modes. The flip
//     is exactly one quorum-signed PolicyChange record, appended to the same
//     append-only store and therefore itself auditable history.
//   - The substrate fiat settlement a coordinator runs with its nodes (e.g.
//     SoHoLINK's Stripe payouts) is a DIFFERENT thing at a different layer and
//     MUST NOT be conflated with member credit here. Enforced by the import
//     graph and by field absence: this package imports only the standard
//     library and sohocloud-protocol/canon, and in ModeEscrow it records no
//     CREDIT at all — Post refuses every spend, so no credit-moving record
//     ever exists, though Enact still records governed PolicyChanges (the
//     escrow->credit flip must itself be auditable history) — fiat-escrowed
//     exchanges live entirely at the coordinator layer this package cannot
//     reference, so no par-value peg between the sovereign unit and fiat
//     ever enters the ledger.
//
// # Absent APIs, and why each is absent
//
//   - No Mint, Grant, Burn, Redeem, Withdraw, Deposit, or Adjust: a mint is
//     the hook every fiat backdoor needs, and a granted token is a saleable,
//     hoardable object. Under mutual credit, issuance IS the spend.
//   - No fiat amount, currency, or denomination field on any type, and no
//     conversion, exchange-rate, bridge, peg, or export API: fungibility with
//     external value must be inexpressible, not merely discouraged.
//   - No memo or free-form metadata field: the ledger is append-only and
//     unerasable, so a text channel would be a PII smuggling channel. Records
//     carry only key-derived account hashes, amounts, nonces, versions, and
//     UTC timestamps; the only strings are Platform, fixed at Genesis, and
//     the string-typed Mode inside stored PolicyChange records — which
//     admission validates against its two enumerated values, so neither is
//     ever caller-authored free text.
//   - No per-account limits, exemption lists, or system-account type: Policy
//     has exactly one DebitCap applying to every account identically, so an
//     operator-held key gets the same issuance well as any member and cannot
//     become a treasury. Deepening the well for everyone requires a public,
//     quorum-signed, ledger-recorded PolicyChange.
//   - No checkpoint, hash chain, or witnessing machinery: external witnessing
//     is internal/record's layer. Open's full replay — every signature,
//     platform binding, nonce, quorum, and admission rule re-verified under
//     the policy in force at each record's position — is this package's audit.
//     History stays a single line even with several live ledgers over one
//     store: Store.Append is conditional on position (ErrConflict), and a
//     ledger that loses the race replays the unseen tail through the same
//     admission rules before retrying, so no fork is ever writable.
//
// # The cross-layer reference
//
// The sole contact with any other layer is Spend.ExchangeHash, a fixed-size
// [32]byte commitment carrying the record entry's leaf ID — the identifier of
// the fully sealed dialog in internal/record. It is opaque and UNCHECKED at
// Post: this package never parses it, never resolves it, and never verifies
// that it names a real sealed entry. A fabricated hash only spends the payer's
// own capped credit. Anchoring a spend to its sealed exchange, if ever wanted,
// is a coordinator/composition-root concern, never an economy dependency — do
// not "fix" the asymmetry by wiring record lookups into this package. The
// same unchecked-ness cuts the other way: ExchangeHash is an unverified
// commitment channel, and a composition root MUST NOT point it at settlement
// artifacts (payout references, invoices, fiat receipt hashes) — the ledger
// cannot detect that misuse, so keeping fiat out of the channel is the
// root's obligation.
//
// # The residual this package cannot remove
//
// Just as the record layer names its steganographic floor, this layer names
// its own: the platform-wide spend store is a pseudonymous
// transaction-metadata graph — who paid whom, when, over which exchange hash.
// Account IDs are platform-scoped key hashes carrying no PII, but the shape of
// the graph itself is inherent to zero-sum mutual credit and is visible to
// whoever holds the store. It is distinct from internal/record's per-operator
// exchange logs, and no API here aggregates, exports, or serializes it — but
// it exists, and callers granting store access should know they are granting
// the graph.
package economy
