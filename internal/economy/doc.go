// Package economy is a STUB. It is not built.
//
// It reserves the place for Cloudy's member economy: member-issued credit
// within the Cloudy platform. This is a JFA member-economy layer that the
// substrate coordination protocol deliberately does not define, and it is
// Cloudy's to own.
//
// When it is built, these Janus-Facing Architecture invariants are NOT
// negotiable:
//
//   - Credit is member-ISSUED, not sold. It MUST NOT be purchasable for fiat
//     and MUST NOT be redeemable back into fiat. It is spend-only within the
//     platform: a claim on the network's goods and services, not a security or
//     a store of external value.
//   - Currency is per-platform and SOVEREIGN. There is no cross-platform unit
//     of account; Cloudy credit is denominated in Cloudy's own unit and MUST
//     NOT be made fungible with another platform's currency.
//   - Escrow-now, credit-later is a single policy switch, not two code paths. A
//     platform may start in fiat-escrow mode and later enable member credit;
//     that transition MUST be one governed configuration change, not a rewrite.
//
// The substrate fiat settlement a coordinator runs with its nodes (e.g.
// SoHoLINK's Stripe payouts) is a DIFFERENT thing at a different layer and MUST
// NOT be conflated with member credit here.
package economy
