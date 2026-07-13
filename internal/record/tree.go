package record

import (
	"crypto/sha256"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// domainNode tags interior Merkle nodes. Leaves keep their own domain
// (drops/leaf/v0, via Entry.ID), so a leaf hash can never be replayed as an
// interior node or vice versa — the RFC 6962 0x00/0x01 prefix discipline,
// expressed with canon domain tags like everything else in the package.
const domainNode = "drops/node/v1"

// nodeHash combines two subtree hashes into their parent.
func nodeHash(left, right Hash) Hash {
	return Hash(sha256.Sum256(canon.New(domainNode).Bytes(left[:]).Bytes(right[:]).Sum()))
}

// largestPow2LT returns the largest power of two strictly less than n;
// n must be >= 2.
func largestPow2LT(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// mth is the Merkle tree head over leaves (RFC 6962 shape): a single leaf is
// its own subtree hash, and a larger tree splits at the largest power of two
// strictly below its size. mth requires at least one leaf; the empty log's
// head is the LogID seed, handled by Log.Checkpoint.
func mth(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := largestPow2LT(uint64(len(leaves)))
	return nodeHash(mth(leaves[:k]), mth(leaves[k:]))
}

// provePath returns the audit path for the leaf at index m within leaves:
// the sibling subtree hashes from leaf-adjacent first to root-adjacent last.
func provePath(m uint64, leaves []Hash) []Hash {
	if len(leaves) == 1 {
		return nil
	}
	k := largestPow2LT(uint64(len(leaves)))
	if m < k {
		return append(provePath(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(provePath(m-k, leaves[k:]), mth(leaves[:k]))
}

// rootFromPath recomputes the tree head implied by placing leaf at index seq
// of a size-entry tree with the given audit path; ok is false when the path
// length does not match the tree shape. Nothing in the path is trusted —
// every hash is recomputed.
func rootFromPath(leaf Hash, seq, size uint64, path []Hash) (Hash, bool) {
	if size == 0 || seq >= size {
		return Hash{}, false
	}
	if size == 1 {
		if len(path) != 0 {
			return Hash{}, false
		}
		return leaf, true
	}
	if len(path) == 0 {
		return Hash{}, false
	}
	k := largestPow2LT(size)
	sibling := path[len(path)-1]
	rest := path[:len(path)-1]
	if seq < k {
		sub, ok := rootFromPath(leaf, seq, k, rest)
		if !ok {
			return Hash{}, false
		}
		return nodeHash(sub, sibling), true
	}
	sub, ok := rootFromPath(leaf, seq-k, size-k, rest)
	if !ok {
		return Hash{}, false
	}
	return nodeHash(sibling, sub), true
}

// proveConsistency returns the RFC 6962 consistency proof between the tree
// over leaves[:m] and the tree over all leaves (m entries -> n entries,
// 0 < m < n <= len(leaves)).
func proveConsistency(m uint64, leaves []Hash) []Hash {
	return subProof(m, leaves, true)
}

func subProof(m uint64, leaves []Hash, complete bool) []Hash {
	n := uint64(len(leaves))
	if m == n {
		if complete {
			// The old tree is exactly this subtree; the verifier already
			// holds its hash (the older checkpoint's head).
			return nil
		}
		return []Hash{mth(leaves)}
	}
	k := largestPow2LT(n)
	if m <= k {
		return append(subProof(m, leaves[:k], complete), mth(leaves[k:]))
	}
	return append(subProof(m-k, leaves[k:], false), mth(leaves[:k]))
}

// consRoots recomputes, from a consistency proof, the (older, newer) tree
// heads it implies. seed is the older checkpoint's head, standing in for the
// omitted subtree hash along the complete-prefix spine (RFC 6962's b=true).
// The proof is consumed root-adjacent end first; ok is false on any shape
// mismatch.
func consRoots(m, n uint64, complete bool, proof []Hash, seed Hash) (older, newer Hash, rest []Hash, ok bool) {
	if m == n {
		if complete {
			return seed, seed, proof, true
		}
		if len(proof) == 0 {
			return Hash{}, Hash{}, nil, false
		}
		h := proof[len(proof)-1]
		return h, h, proof[:len(proof)-1], true
	}
	if m > n || len(proof) == 0 {
		return Hash{}, Hash{}, nil, false
	}
	k := largestPow2LT(n)
	last := proof[len(proof)-1]
	rest = proof[:len(proof)-1]
	if m <= k {
		oldR, newR, remaining, subOK := consRoots(m, k, complete, rest, seed)
		if !subOK {
			return Hash{}, Hash{}, nil, false
		}
		// last is the hash of the new entries' subtree (leaves[k:n]); the
		// old tree lies entirely in the left subtree.
		return oldR, nodeHash(newR, last), remaining, true
	}
	oldR, newR, remaining, subOK := consRoots(m-k, n-k, false, rest, seed)
	if !subOK {
		return Hash{}, Hash{}, nil, false
	}
	// last is the full left subtree (leaves[:k]), shared by both trees.
	return nodeHash(last, oldR), nodeHash(last, newR), remaining, true
}
