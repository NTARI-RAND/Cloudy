package techtree

// Weight is a claim's citation weight: a LEGIBLE, FORKABLE breakdown of the
// inbound edges pointing at it, counted by kind and by DISTINCT asserter. It is
// deliberately NOT a single score and there is deliberately no method that
// collapses it into one — a scalar "truth rank" would be the single index of
// what's-good that Part III forbids (a chokepoint wearing a scholar's gown).
// A consumer decides how to weigh these fields, and can re-derive them from the
// log, so the weighting stays contestable rather than authoritative.
//
// ECONOMICALLY INERT. Per Part III, citation weight MUST size zero economic
// reward until the Sybil approach (open problem 4) is settled. Counting by
// distinct asserter key is a weak mitigation, NOT Sybil-resistance: one actor
// with many keys inflates every field here. Nothing in Cloudy pays or
// ranks-for-sale on these numbers; they inform human discovery only.
type Weight struct {
	Cites      int // distinct asserters who cite this claim
	BuildsOn   int // distinct asserters whose claims build on this one
	Reproduces int // distinct asserters who independently reproduced it
	Refutes    int // distinct asserters whose reproduction failed
	Contests   int // distinct asserters contesting it
}

// CitationWeight computes the inbound-edge breakdown for a claim by scanning
// the append-ordered log. Each (kind) counts DISTINCT asserter keys, so drawing
// ten edges of one kind from one member counts once. Unknown claim ids yield a
// zero Weight (a claim with no inbound edges legitimately has zero — absence is
// not an error). Deterministic: same log, same result.
func (t *Tree) CitationWeight(id ClaimID) Weight {
	// Per kind, the set of distinct asserter keys (hex of the key) pointing To id.
	seen := map[RefKind]map[string]bool{}
	mark := func(k RefKind, asserterHex string) {
		m := seen[k]
		if m == nil {
			m = map[string]bool{}
			seen[k] = m
		}
		m[asserterHex] = true
	}
	for _, it := range t.log {
		r := it.Reference
		if r == nil || r.To != id {
			continue
		}
		mark(r.Kind, string(r.Asserter))
	}
	return Weight{
		Cites:      len(seen[RefCites]),
		BuildsOn:   len(seen[RefBuildsOn]),
		Reproduces: len(seen[RefReproduces]),
		Refutes:    len(seen[RefRefutes]),
		Contests:   len(seen[RefContests]),
	}
}
