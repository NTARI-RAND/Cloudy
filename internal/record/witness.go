package record

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// domainWitness tags witness countersignature payloads, distinct from the
// checkpoint tag, so an operator signature can never pose as a witness
// cosignature or vice versa.
const domainWitness = "drops/witness/v1"

// witnessPayload is the canonical payload a witness countersigns: the
// checkpoint's canonical bytes wrapped under the witness domain tag.
func witnessPayload(cp Checkpoint) []byte {
	return canon.New(domainWitness).Bytes(cp.CanonicalBytes()).Sum()
}

// Countersignature is one independent witness's signature over a checkpoint,
// under the distinct witness domain tag so an operator signature can never
// pose as a witness cosignature or vice versa. Witness keys are resolved and
// trusted out-of-band; the package distributes no keys.
type Countersignature struct {
	Witness   ed25519.PublicKey
	Signature []byte
}

// Verify reports whether the countersignature is a valid witness signature
// over cp under the witness domain tag.
func (cs Countersignature) Verify(cp Checkpoint) bool {
	return len(cs.Witness) == ed25519.PublicKeySize &&
		len(cs.Signature) == ed25519.SignatureSize &&
		ed25519.Verify(cs.Witness, witnessPayload(cp), cs.Signature)
}

// Witness is an independent countersigner and the package's ONLY way to
// produce a Countersignature. Its single verb is Countersign, taken after
// the fact over published checkpoints: Log.Append takes no witness
// parameter, so a witness structurally cannot approve, veto, or author
// entries.
//
// A Witness's rollback/fork memory (the last checkpoint it cosigned per
// log) is process-volatile: a reconstructed Witness reverts to
// trust-on-first-checkpoint and WILL cosign a rewritten head it would
// previously have refused. A deployment MUST therefore run each witness as
// a single long-lived value; durability of its state across restarts is a
// deployment concern this package does not solve. The damage is bounded
// regardless: older cosigned checkpoints remain portable fork evidence, so
// a rewrite cosigned after amnesia is still cryptographically visible to
// anyone holding an earlier WitnessedCheckpoint.
type Witness struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	last map[Hash]Checkpoint // per LogID, the last checkpoint this witness cosigned
}

// NewWitness returns a witness holding priv; its first sight of a log is
// trust-on-first-checkpoint, after which only chain-consistent extensions
// are cosigned.
func NewWitness(priv ed25519.PrivateKey) *Witness {
	w := &Witness{
		priv: priv,
		last: make(map[Hash]Checkpoint),
	}
	if len(priv) == ed25519.PrivateKeySize {
		w.pub = priv.Public().(ed25519.PublicKey)
	}
	return w
}

// Key returns the witness's public key.
func (w *Witness) Key() ed25519.PublicKey {
	return w.pub
}

// Countersign verifies cp under operator, refuses when operator equals the
// witness's own key, refuses any rollback or fork against the last
// checkpoint it cosigned for cp.Log (using the RFC-6962 consistency proof as
// extension evidence via VerifyConsistency; Log.ProveConsistency produces
// it), then returns its cosignature and remembers cp. Countersigning a
// rewritten head is the one thing a witness exists to never do, and here it
// is enforced, not advised.
func (w *Witness) Countersign(cp Checkpoint, operator ed25519.PublicKey, consistencyProof []Hash) (Countersignature, error) {
	return w.CountersignAs(cp, operator, LogID(operator), consistencyProof)
}

// CountersignAs is Countersign with an explicit log identity, so the same
// witness (and the same per-log rollback memory, keyed by log identity)
// serves dialog logs and lifecycle logs alike.
func (w *Witness) CountersignAs(cp Checkpoint, operator ed25519.PublicKey, wantLog Hash, consistencyProof []Hash) (Countersignature, error) {
	if len(w.priv) != ed25519.PrivateKeySize {
		return Countersignature{}, errors.New("record: witness key is malformed")
	}
	if bytes.Equal(operator, w.pub) {
		return Countersignature{}, errors.New("record: a witness never countersigns its own operator")
	}
	if !cp.VerifyAs(operator, wantLog) {
		return Countersignature{}, errors.New("record: checkpoint does not verify under operator for this log")
	}
	if prev, seen := w.last[cp.Log]; seen {
		if !VerifyConsistencyAs(prev, cp, consistencyProof, operator, wantLog) {
			return Countersignature{}, errors.New("record: checkpoint is not a consistent extension of the last cosigned checkpoint (rollback or fork refused)")
		}
	}
	cs := Countersignature{
		Witness:   w.pub,
		Signature: ed25519.Sign(w.priv, witnessPayload(cp)),
	}
	w.last[cp.Log] = cp
	return cs, nil
}

// WitnessedCheckpoint is the publishable unit: an operator checkpoint plus
// the countersignatures of witnesses that have seen it. Witnesses federate
// by independently appending countersignatures; no quorum, vote, or
// coordination among witnesses is defined here or anywhere.
type WitnessedCheckpoint struct {
	Checkpoint        Checkpoint
	Countersignatures []Countersignature
}

// Verify reports whether the operator signature and every countersignature
// verify and the witnesses are independent: pairwise-distinct keys, none
// equal to the operator's — an operator can never be its own witness.
func (w WitnessedCheckpoint) Verify(operator ed25519.PublicKey) bool {
	if !w.Checkpoint.Verify(operator) {
		return false
	}
	seen := make(map[string]bool, len(w.Countersignatures))
	for _, cs := range w.Countersignatures {
		if !cs.Verify(w.Checkpoint) {
			return false
		}
		if bytes.Equal(cs.Witness, operator) {
			return false
		}
		k := string(cs.Witness)
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

// StandIn reports whether fewer than two VERIFIED, independent witnesses
// have countersigned: only countersignatures that Verify against the
// bundle's checkpoint, whose keys are pairwise distinct (Verify pins them to
// valid ed25519 length), and whose keys differ from operator are counted.
// Counting only verified, operator-independent cosignatures makes the label
// meaningful on its own — a bundle padded with garbage or operator-authored
// cosignatures still reads as the stand-in it is, whether or not the caller
// also checks Verify. Per the anchor/ model a deployment presenting a
// stand-in checkpoint MUST surface this label to members.
func (w WitnessedCheckpoint) StandIn(operator ed25519.PublicKey) bool {
	distinct := make(map[string]bool, len(w.Countersignatures))
	for _, cs := range w.Countersignatures {
		if !cs.Verify(w.Checkpoint) || bytes.Equal(cs.Witness, operator) {
			continue
		}
		distinct[string(cs.Witness)] = true
	}
	return len(distinct) < 2
}
