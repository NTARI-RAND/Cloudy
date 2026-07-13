package record

import (
	"fmt"
	"testing"
)

// syntheticLeaves returns n distinct deterministic leaf hashes.
func syntheticLeaves(n int) []Hash {
	leaves := make([]Hash, n)
	for i := range leaves {
		leaves[i] = HashContent([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return leaves
}

// TestMerkleInclusionExhaustive proves every leaf of every tree size up to 33
// (crossing several power-of-two boundaries) against the tree head, and
// rejects every single-bit tamper of position, path, and leaf.
func TestMerkleInclusionExhaustive(t *testing.T) {
	for n := 1; n <= 33; n++ {
		leaves := syntheticLeaves(n)
		root := mth(leaves)
		for m := 0; m < n; m++ {
			path := provePath(uint64(m), leaves)
			got, ok := rootFromPath(leaves[m], uint64(m), uint64(n), path)
			if !ok || got != root {
				t.Fatalf("n=%d m=%d: honest audit path does not recompute the head", n, m)
			}
			// Wrong position never verifies (every other position).
			for wrong := 0; wrong < n; wrong++ {
				if wrong == m {
					continue
				}
				if got, ok := rootFromPath(leaves[m], uint64(wrong), uint64(n), path); ok && got == root {
					t.Fatalf("n=%d m=%d: path verified at wrong position %d", n, m, wrong)
				}
			}
			// Tampered path element never verifies.
			if len(path) > 0 {
				bad := append([]Hash(nil), path...)
				bad[0][0] ^= 1
				if got, ok := rootFromPath(leaves[m], uint64(m), uint64(n), bad); ok && got == root {
					t.Fatalf("n=%d m=%d: tampered path verified", n, m)
				}
			}
			// Wrong leaf never verifies.
			wrongLeaf := HashContent([]byte("not a leaf"))
			if got, ok := rootFromPath(wrongLeaf, uint64(m), uint64(n), path); ok && got == root {
				t.Fatalf("n=%d m=%d: foreign leaf verified", n, m)
			}
			// Truncated and padded paths never verify.
			if len(path) > 0 {
				if got, ok := rootFromPath(leaves[m], uint64(m), uint64(n), path[:len(path)-1]); ok && got == root {
					t.Fatalf("n=%d m=%d: truncated path verified", n, m)
				}
			}
			padded := append(append([]Hash(nil), path...), Hash{})
			if got, ok := rootFromPath(leaves[m], uint64(m), uint64(n), padded); ok && got == root {
				t.Fatalf("n=%d m=%d: padded path verified", n, m)
			}
		}
	}
}

// TestMerkleConsistencyExhaustive proves every (older, newer) size pair up to
// 33 and rejects tampers, prefix rewrites, and cross-pair replays.
func TestMerkleConsistencyExhaustive(t *testing.T) {
	const max = 33
	leaves := syntheticLeaves(max)
	roots := make([]Hash, max+1) // roots[k] = MTH(leaves[:k]), k >= 1
	for k := 1; k <= max; k++ {
		roots[k] = mth(leaves[:k])
	}
	verify := func(m, n uint64, oldRoot, newRoot Hash, proof []Hash) bool {
		oldR, newR, rest, ok := consRoots(m, n, true, proof, oldRoot)
		return ok && len(rest) == 0 && oldR == oldRoot && newR == newRoot
	}
	for n := 2; n <= max; n++ {
		for m := 1; m < n; m++ {
			proof := proveConsistency(uint64(m), leaves[:n])
			if !verify(uint64(m), uint64(n), roots[m], roots[n], proof) {
				t.Fatalf("m=%d n=%d: honest consistency proof rejected", m, n)
			}
			// Tampered proof element.
			if len(proof) > 0 {
				bad := append([]Hash(nil), proof...)
				bad[len(bad)/2][0] ^= 1
				if verify(uint64(m), uint64(n), roots[m], roots[n], bad) {
					t.Fatalf("m=%d n=%d: tampered consistency proof accepted", m, n)
				}
			}
			// A rewritten prefix (different old root) must not verify with any
			// honest proof for this pair.
			forged := roots[m]
			forged[0] ^= 1
			if verify(uint64(m), uint64(n), forged, roots[n], proof) {
				t.Fatalf("m=%d n=%d: rewritten prefix accepted", m, n)
			}
			// A different new root must not verify.
			forgedNew := roots[n]
			forgedNew[0] ^= 1
			if verify(uint64(m), uint64(n), roots[m], forgedNew, proof) {
				t.Fatalf("m=%d n=%d: forged new head accepted", m, n)
			}
		}
	}
	// Cross-pair replay: a proof for (m1,n) never verifies as (m2,n), m1 != m2.
	n := uint64(21)
	for m1 := uint64(1); m1 < n; m1++ {
		proof := proveConsistency(m1, leaves[:n])
		for m2 := uint64(1); m2 < n; m2++ {
			if m1 == m2 {
				continue
			}
			if verify(m2, n, roots[m2], roots[n], proof) {
				t.Fatalf("proof for m=%d replayed as m=%d (n=%d)", m1, m2, n)
			}
		}
	}
}

// TestLogProveConsistencyMatchesTree ties Log.ProveConsistency to the tree
// primitives through the public API, over a real appended log.
func TestLogProveConsistencyMatchesTree(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)
	l, err := OpenLog(op.pub, NewMemStore())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	sign := func(cp Checkpoint) Checkpoint {
		cp.Sign(op.priv)
		return cp
	}
	var cps []Checkpoint
	cps = append(cps, sign(l.Checkpoint(testInstant)))
	for i := 0; i < 9; i++ {
		e := sealedEntry(t, id, a, b, contentN(byte(40+i)), Hash{}, testInstant)
		if _, err := l.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
		cps = append(cps, sign(l.Checkpoint(testInstant)))
	}
	for older := 0; older <= 9; older++ {
		proof, err := l.ProveConsistency(uint64(older))
		if err != nil {
			t.Fatalf("ProveConsistency(%d): %v", older, err)
		}
		if !VerifyConsistency(cps[older], cps[9], proof, op.pub) {
			t.Fatalf("consistency %d -> 9 rejected", older)
		}
	}
	if _, err := l.ProveConsistency(10); err == nil {
		t.Fatal("ProveConsistency beyond the log size must error")
	}
}
