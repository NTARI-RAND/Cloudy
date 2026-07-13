package record

import (
	"crypto/ed25519"
)

// Proof is what a member keeps beside an entry to later prove its inclusion
// under a checkpoint, offline and without the operator: the entry's sequence
// number and its RFC-6962 audit path — ~log2(size) hashes however large the
// log grows, which is what makes verification feasible on an entry-level
// device (the open-problem-8 floor). Nothing in it is trusted: verification
// recomputes every hash.
type Proof struct {
	Seq  uint64 // the entry's position in the log
	Path []Hash // sibling subtree hashes, leaf-adjacent first, root-adjacent last
}

// VerifyInclusion reports whether e is a fully sealed covenant committed at
// position p.Seq of cp's log: it requires e.Verify(), cp.Verify(operator),
// e.Log == cp.Log, and that the audit path recomputes cp.Head from e.ID().
// One call checks everything; there is no half-verification to forget. It
// does NOT prove non-inclusion or liveness: an operator that never appended
// the entry simply cannot produce a proof.
func VerifyInclusion(e Entry, p Proof, cp Checkpoint, operator ed25519.PublicKey) bool {
	if !e.Verify() {
		return false
	}
	if !cp.Verify(operator) {
		return false
	}
	if e.Log != cp.Log {
		return false
	}
	root, ok := rootFromPath(e.ID(), p.Seq, cp.Size, p.Path)
	return ok && root == cp.Head
}

// VerifyConsistency reports whether newer extends older without rewrite:
// both checkpoints verify under operator, same Log, and the RFC-6962
// consistency proof recomputes BOTH heads — older.Head from its components
// and newer.Head from the same components plus the extension. Failure
// against two operator-signed checkpoints is portable fork evidence — this
// is how any member or witness detects a silent edit or deletion. It proves
// nothing about entries the older checkpoint never covered.
//
// The empty older log (Size 0) is consistent with anything on an empty
// proof; equal sizes are consistent only when the heads are equal.
func VerifyConsistency(older, newer Checkpoint, proof []Hash, operator ed25519.PublicKey) bool {
	if !older.Verify(operator) || !newer.Verify(operator) {
		return false
	}
	if older.Log != newer.Log {
		return false
	}
	switch {
	case older.Size > newer.Size:
		return false
	case older.Size == 0:
		return len(proof) == 0
	case older.Size == newer.Size:
		return len(proof) == 0 && older.Head == newer.Head
	}
	oldR, newR, rest, ok := consRoots(older.Size, newer.Size, true, proof, older.Head)
	return ok && len(rest) == 0 && oldR == older.Head && newR == newer.Head
}
