package techtree

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Errors returned when an artifact violates a tree invariant.
var (
	ErrWrongPlatform = errors.New("techtree: artifact platform does not match the tree")
	ErrBadSignature  = errors.New("techtree: artifact failed signature verification")
	ErrDuplicate     = errors.New("techtree: artifact already in the tree")
	ErrUnknownClaim  = errors.New("techtree: reference names a claim not in the tree")
	ErrNotAsserter   = errors.New("techtree: reference asserter is not the claimant of its From claim")
	ErrBuildsOnCycle = errors.New("techtree: builds_on edge would create a dependency cycle")
	ErrEmptyPlatform = errors.New("techtree: tree platform must be set")
)

// Item is one entry in the append-only log: exactly one of Claim or Reference
// is non-nil. Item is the unit of replay and of future witnessing.
type Item struct {
	Claim     *Claim
	Reference *Reference
}

// Tree is an append-only, hash-chained log of claims and references scoped to a
// single platform. Every artifact is verified on insert; the chain head folds
// each artifact's leaf ID so any reordering or tampering is detectable; OpenLog
// replays and re-verifies the whole log. It is a single-writer StandIn until
// the shared record witnessing lands (see doc.go).
type Tree struct {
	platform string
	claims   map[ClaimID]Claim
	refs     map[RefID]Reference
	log      []Item
	head     Hash
}

// Hash is an opaque 32-byte digest — the chain head type. It matches the width
// other Cloudy layers use for opaque references.
type Hash [32]byte

// NewTree returns an empty tree bound to platform.
func NewTree(platform string) (*Tree, error) {
	if platform == "" {
		return nil, ErrEmptyPlatform
	}
	return &Tree{
		platform: platform,
		claims:   make(map[ClaimID]Claim),
		refs:     make(map[RefID]Reference),
	}, nil
}

// Platform returns the platform this tree is bound to.
func (t *Tree) Platform() string { return t.platform }

// Head returns the current chain head (zero for an empty tree). It is the value
// a future checkpoint would sign to a witness.
func (t *Tree) Head() Hash { return t.head }

// fold advances the chain head over a newly accepted artifact's leaf ID.
func (t *Tree) fold(leaf []byte) {
	b := canon.New(domainChain)
	b.Bytes(t.head[:])
	b.Bytes(leaf)
	t.head = Hash(sha256.Sum256(b.Sum()))
}

// AddClaim verifies a claim, rejects a cross-platform or duplicate one, and
// appends it. It returns the claim's ID.
func (t *Tree) AddClaim(c Claim) (ClaimID, error) {
	if c.Platform != t.platform {
		return ClaimID{}, ErrWrongPlatform
	}
	if !c.Verify() {
		return ClaimID{}, ErrBadSignature
	}
	id := c.ID()
	if _, ok := t.claims[id]; ok {
		return ClaimID{}, ErrDuplicate
	}
	// Store a defensive copy so a caller mutating key/sig slices afterward
	// cannot alter accepted history (same discipline as the memstores).
	t.claims[id] = cloneClaim(c)
	t.log = append(t.log, Item{Claim: cloneClaimPtr(c)})
	t.fold(id[:])
	return id, nil
}

// AddReference verifies an edge and enforces the graph invariants: From and To
// claims must already exist, the asserter must be the claimant of From, and a
// builds_on edge must not create a dependency cycle. It returns the edge's ID.
func (t *Tree) AddReference(r Reference) (RefID, error) {
	if r.Platform != t.platform {
		return RefID{}, ErrWrongPlatform
	}
	if !r.Verify() {
		return RefID{}, ErrBadSignature
	}
	from, ok := t.claims[r.From]
	if !ok {
		return RefID{}, fmt.Errorf("%w: From %x", ErrUnknownClaim, r.From[:6])
	}
	if _, ok := t.claims[r.To]; !ok {
		return RefID{}, fmt.Errorf("%w: To %x", ErrUnknownClaim, r.To[:6])
	}
	if !r.Asserter.Equal(from.Claimant) {
		return RefID{}, ErrNotAsserter
	}
	if r.Kind == RefBuildsOn && t.buildsOnReaches(r.To, r.From) {
		// To already (transitively) builds on From, so From→To closes a loop.
		return RefID{}, ErrBuildsOnCycle
	}
	id := r.ID()
	if _, ok := t.refs[id]; ok {
		return RefID{}, ErrDuplicate
	}
	t.refs[id] = cloneRef(r)
	t.log = append(t.log, Item{Reference: cloneRefPtr(r)})
	t.fold(id[:])
	return id, nil
}

// buildsOnReaches reports whether `start` can reach `target` by following
// builds_on edges (start builds_on ... builds_on target). Used to reject a new
// builds_on edge that would close a cycle. O(V+E) DFS over accepted edges.
func (t *Tree) buildsOnReaches(start, target ClaimID) bool {
	if start == target {
		return true
	}
	seen := map[ClaimID]bool{}
	stack := []ClaimID{start}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			continue
		}
		seen[n] = true
		for _, it := range t.log {
			r := it.Reference
			if r == nil || r.Kind != RefBuildsOn || r.From != n {
				continue
			}
			if r.To == target {
				return true
			}
			stack = append(stack, r.To)
		}
	}
	return false
}

// Claim returns a copy of a stored claim and whether it exists.
func (t *Tree) Claim(id ClaimID) (Claim, bool) {
	c, ok := t.claims[id]
	if !ok {
		return Claim{}, false
	}
	return cloneClaim(c), true
}

// Log returns the append-ordered log (defensive copies), for replay via
// OpenLog and for future witnessing.
func (t *Tree) Log() []Item {
	out := make([]Item, len(t.log))
	for i, it := range t.log {
		if it.Claim != nil {
			out[i] = Item{Claim: cloneClaimPtr(*it.Claim)}
		} else {
			out[i] = Item{Reference: cloneRefPtr(*it.Reference)}
		}
	}
	return out
}

// OpenLog rebuilds a tree from an ordered log, re-verifying every artifact and
// re-enforcing every invariant through the same Add path used originally. A
// tampered, reordered, or forged log fails here rather than being trusted.
// This is techtree's counterpart to record.OpenLog.
func OpenLog(platform string, items []Item) (*Tree, error) {
	t, err := NewTree(platform)
	if err != nil {
		return nil, err
	}
	for i, it := range items {
		switch {
		case it.Claim != nil && it.Reference != nil:
			return nil, fmt.Errorf("techtree: log item %d has both a claim and a reference", i)
		case it.Claim != nil:
			if _, err := t.AddClaim(*it.Claim); err != nil {
				return nil, fmt.Errorf("techtree: replay claim at %d: %w", i, err)
			}
		case it.Reference != nil:
			if _, err := t.AddReference(*it.Reference); err != nil {
				return nil, fmt.Errorf("techtree: replay reference at %d: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("techtree: log item %d is empty", i)
		}
	}
	return t, nil
}

func cloneClaim(c Claim) Claim {
	c.Claimant = append(ed25519.PublicKey(nil), c.Claimant...)
	c.Signature = append([]byte(nil), c.Signature...)
	return c
}

func cloneClaimPtr(c Claim) *Claim { cc := cloneClaim(c); return &cc }

func cloneRef(r Reference) Reference {
	r.Asserter = append(ed25519.PublicKey(nil), r.Asserter...)
	r.Signature = append([]byte(nil), r.Signature...)
	return r
}

func cloneRefPtr(r Reference) *Reference { rr := cloneRef(r); return &rr }
