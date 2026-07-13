package record

import (
	"crypto/ed25519"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// domainCheckpoint tags checkpoint signing payloads; an operator's
// checkpoint signature is never valid under any other tag, so it can never
// pose as a member seal or a witness countersignature.
const domainCheckpoint = "drops/checkpoint/v1"

// Checkpoint is an operator's signed, monotonic commitment to its log head —
// the Certificate Transparency signed tree head. v1: Head is the RFC-6962
// Merkle tree head over the leaf IDs (the v0 linear fold is gone, decided
// 2026-07-12 before any durable log existed).
type Checkpoint struct {
	Log       Hash      // LogID of the operator's log
	Size      uint64    // number of entries committed
	Head      Hash      // Merkle tree head over leaves [0, Size); the LogID seed when Size == 0
	IssuedAt  time.Time // UTC
	Signature []byte    // ed25519 by the operator; excluded from CanonicalBytes
}

// CanonicalBytes returns the deterministic signing payload (checkpoint
// domain tag) with Signature excluded.
func (c Checkpoint) CanonicalBytes() []byte {
	b := canon.New(domainCheckpoint)
	b.Bytes(c.Log[:])
	b.Uint64(c.Size)
	b.Bytes(c.Head[:])
	b.Time(c.IssuedAt)
	return b.Sum()
}

// Sign sets Signature using the operator's private key.
func (c *Checkpoint) Sign(priv ed25519.PrivateKey) {
	c.Signature = ed25519.Sign(priv, c.CanonicalBytes())
}

// Verify reports whether Signature is a valid operator signature AND
// c.Log == LogID(operator) — the operator's DIALOG log. A checkpoint can
// never be replayed against another operator's log, and (because the
// lifecycle log has a domain-distinct identity) never against the same
// operator's lifecycle log either.
func (c Checkpoint) Verify(operator ed25519.PublicKey) bool {
	return c.VerifyAs(operator, LogID(operator))
}

// VerifyAs reports whether Signature is a valid signature by signer AND
// c.Log equals the expected log identity — the generic binding used for the
// lifecycle log (VerifyAs(operator, LifecycleLogID(operator))) and any
// future per-operator log kind.
func (c Checkpoint) VerifyAs(signer ed25519.PublicKey, wantLog Hash) bool {
	return len(signer) == ed25519.PublicKeySize &&
		len(c.Signature) == ed25519.SignatureSize &&
		c.Log == wantLog &&
		ed25519.Verify(signer, c.CanonicalBytes(), c.Signature)
}
