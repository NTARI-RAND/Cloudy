// Package opcred is Cloudy's custody of the operator credential: the client
// half of the protocol's Layer C (operator identity). It owns the seven-key
// Ed25519 keyset an operator holds, signs live transmissions with two of the
// seven keys (the 2-of-7 discipline), answers coordinator onboarding
// conformance challenges, and anchors the keyset to a root of trust through a
// short-lived signed delegation.
//
// Invariants:
//
//   - Leaf discipline. opcred imports only the standard library and the
//     protocol module (operator + canon). No HTTP, no UI, no imports of other
//     Cloudy internal packages.
//   - Private keys live ONLY in the keyset directory (as 32-byte seeds) and in
//     process memory. They are NEVER serialized into any message, log line, or
//     command output. Only public keys are exported for registration.
//   - Every signature goes through the protocol's own types (Sign over
//     CanonicalBytes), so the protocol's Verify is always the oracle.
//   - The root of trust is a seam (RootSigner). The shipped implementation is
//     file-backed and labels itself StandIn()==true; a device/HSM
//     implementation slots in behind the same interface with no changes to
//     Delegation issue/verify.
//
// Composition-root wiring (constructing a TransmissionSigner inside
// cmd/cloudy and refusing to sign without a live delegation) is a deliberate
// follow-up; this package provides the custody structure only.
package opcred
