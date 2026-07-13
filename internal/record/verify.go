package record

import (
	"crypto/ed25519"
)

// Proof is what a member keeps beside an entry to later prove its inclusion
// under a checkpoint, offline and without the operator. Nothing in it is
// trusted: verification recomputes every hash.
type Proof struct {
	Prior Hash   // chain head immediately before the entry (the LogID seed for the first entry)
	Links []Hash // leaf hashes (Entry.ID) of every later entry up to the checkpointed head
}

// VerifyInclusion reports whether e is a fully sealed covenant committed at
// position cp.Size-1-len(p.Links) of cp's log: it requires e.Verify(),
// cp.Verify(operator), e.Log == cp.Log, and that folding e.ID() over p.Prior
// and p.Links yields cp.Head. One call checks everything; there is no
// half-verification to forget. It does NOT prove non-inclusion or liveness:
// an operator that never appended the entry simply cannot produce a proof.
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
	if cp.Size < uint64(len(p.Links))+1 {
		return false
	}
	h := chainStep(p.Prior, e.ID())
	for _, link := range p.Links {
		h = chainStep(h, link)
	}
	return h == cp.Head
}

// VerifyConsistency reports whether newer extends older without rewrite:
// both checkpoints verify under operator, same Log,
// newer.Size == older.Size+len(links), and folding links over older.Head
// yields newer.Head. Failure against two operator-signed checkpoints is
// portable fork evidence — this is how any member or witness detects a
// silent edit or deletion. It proves nothing about entries the older
// checkpoint never covered.
func VerifyConsistency(older, newer Checkpoint, links []Hash, operator ed25519.PublicKey) bool {
	if !older.Verify(operator) || !newer.Verify(operator) {
		return false
	}
	if older.Log != newer.Log {
		return false
	}
	if newer.Size != older.Size+uint64(len(links)) {
		return false
	}
	h := older.Head
	for _, link := range links {
		h = chainStep(h, link)
	}
	return h == newer.Head
}
