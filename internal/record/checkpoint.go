package record

import (
	"crypto/ed25519"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// domainCheckpoint tags checkpoint signing payloads; an operator's
// checkpoint signature is never valid under any other tag, so it can never
// pose as a member seal or a witness countersignature.
const domainCheckpoint = "cloudy/record/checkpoint/v0"

// Checkpoint is an operator's signed, monotonic commitment to its log head —
// the Certificate Transparency signed-tree-head analogue for a linear chain.
type Checkpoint struct {
	Log       Hash      // LogID of the operator's log
	Size      uint64    // number of entries committed
	Head      Hash      // chain hash after entry Size-1 (fold seeded with Log); the LogID seed when Size == 0
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
// c.Log == LogID(operator), so a checkpoint can never be replayed against
// another operator's log.
func (c Checkpoint) Verify(operator ed25519.PublicKey) bool {
	return len(operator) == ed25519.PublicKeySize &&
		len(c.Signature) == ed25519.SignatureSize &&
		c.Log == LogID(operator) &&
		ed25519.Verify(operator, c.CanonicalBytes(), c.Signature)
}
