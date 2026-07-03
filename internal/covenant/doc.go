// Package covenant is a STUB. It is not built.
//
// It reserves the place for Cloudy's reputation covenant: how members come to
// trust one another on the platform. This is a JFA member-economy layer the
// substrate coordination protocol does not define.
//
// When it is built, these Janus-Facing Architecture invariants are NOT
// negotiable:
//
//   - Reputation is a full DISTRIBUTION, never a single averaged score. A
//     member's standing is the shape of all its assessments; it MUST NOT be
//     collapsed to one number, because averaging erases the variance that is
//     the actual signal.
//   - Reputation is not currency. It MUST NOT be purchasable, transferable, or
//     redeemable.
//
// Cross-platform reputation PORTABILITY is an open problem (#5) and is
// deliberately undecided. This package MUST NOT bake in a portability mechanism
// as a side effect of building single-platform reputation; whether and how
// reputation crosses platform boundaries is a governance decision left open.
package covenant
