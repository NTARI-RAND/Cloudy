package record

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// The claim-lifecycle log. Part IV of the architecture: "the witnessed unit
// is the claim lifecycle, not only the sealed verdict" — a harm claim's
// filing, adjudication, resolution, and seal each commit to the witnessed
// record AS THEY HAPPEN, a sequence of monotonic, independently-witnessed
// transitions, never one terminal block delivered whole.
//
// The lifecycle log is a SECOND per-operator Merkle log, wholly disjoint
// from the dialog log by domain tags: its log identity, leaves, and
// checkpoint payloads all carry lifecycle-specific tags, so no lifecycle
// artifact can ever pose as a dialog artifact or vice versa. Transitions are
// operator-RECORDED structural facts (claim id, kind, artifact hash,
// exchange ref, instant) — no narrative, no party keys beyond what the
// dispute registry already carries, no PII. Their integrity comes from the
// same place the dialog log's does: operator-signed monotonic checkpoints,
// independently countersigned. The FILING transition additionally has an
// upstream twin — the FilingCommitment lodged at an independent witness
// BEFORE the operator acts (filing.go) — so an operator that never logs a
// filed claim is caught by cross-checking witness receipts against its
// lifecycle log, and an operator that files late is caught by the receipt's
// earlier instant.
const (
	domainLifeLogID      = "drops/lifecycle-logid/v1"
	domainLifeTransition = "drops/lifecycle-transition/v1"
	domainLifeLeaf       = "drops/lifecycle-leaf/v1"
)

// LifecycleLogID derives the identity of an operator's lifecycle log —
// distinct by domain from the same operator's dialog LogID, so checkpoints
// can never be replayed between the two logs.
func LifecycleLogID(operator ed25519.PublicKey) Hash {
	return Hash(sha256.Sum256(canon.New(domainLifeLogID).Bytes(operator).Sum()))
}

// TransitionKind is a claim's position in the lifecycle pipeline.
type TransitionKind uint8

const (
	// KindFiled: the claim exists. Its upstream twin is the FilingCommitment
	// at an independent witness; the operator's own Filed transition is the
	// downstream acknowledgment.
	KindFiled TransitionKind = iota + 1
	// KindAdjudicated: the operator's panel produced a ruling artifact.
	KindAdjudicated
	// KindResolved: the claim reached an outcome (ruling accepted, or the
	// complainant withdrew). Dwell — the age of a claim not yet resolved —
	// is read from the gap after KindFiled; a clock never force-seals it.
	KindResolved
	// KindSealed: the underlying dialog sealed with the claim answered.
	KindSealed
)

// String names the kind for legible surfaces.
func (k TransitionKind) String() string {
	switch k {
	case KindFiled:
		return "filed"
	case KindAdjudicated:
		return "adjudicated"
	case KindResolved:
		return "resolved"
	case KindSealed:
		return "sealed"
	}
	return "invalid"
}

// Transition is one structural fact about one claim: fixed-size hashes, a
// kind, and a UTC instant — no string field, no narrative, no identity
// beyond opaque references. The artifact hash commits to the dispute-layer
// artifact (opening, ruling, withdrawal) whose bytes live in the dispute
// registry's own append-only store; the lifecycle log holds only the digest.
type Transition struct {
	Log      Hash           // LifecycleLogID of the one operator lifecycle log this may enter
	Claim    Hash           // opaque claim id (the dispute layer's DisputeID, held by value)
	Kind     TransitionKind // filed | adjudicated | resolved | sealed
	Artifact Hash           // digest of the transition's artifact bytes; opaque here
	Exchange Hash           // leaf ID of the disputed sealed dialog
	At       time.Time      // UTC instant the transition was recorded
}

// CanonicalBytes returns the deterministic encoding of the transition.
func (t Transition) CanonicalBytes() []byte {
	b := canon.New(domainLifeTransition)
	b.Bytes(t.Log[:])
	b.Bytes(t.Claim[:])
	b.Uint64(uint64(t.Kind))
	b.Bytes(t.Artifact[:])
	b.Bytes(t.Exchange[:])
	b.Time(t.At)
	return b.Sum()
}

// ID returns the transition's leaf hash in the lifecycle tree.
func (t Transition) ID() Hash {
	return Hash(sha256.Sum256(canon.New(domainLifeLeaf).Bytes(t.CanonicalBytes()).Sum()))
}

// TransitionStore is the lifecycle log's append-only persistence surface;
// update and delete are absent verbs, exactly as in Store.
type TransitionStore interface {
	Append(t Transition) error
	At(seq uint64) (Transition, error)
	Len() (uint64, error)
}

// MemTransitionStore is the in-memory TransitionStore.
type MemTransitionStore struct {
	transitions []Transition
}

// NewMemTransitionStore returns an empty in-memory transition store.
func NewMemTransitionStore() *MemTransitionStore {
	return &MemTransitionStore{}
}

// Append implements TransitionStore.
func (s *MemTransitionStore) Append(t Transition) error {
	s.transitions = append(s.transitions, t)
	return nil
}

// At implements TransitionStore.
func (s *MemTransitionStore) At(seq uint64) (Transition, error) {
	if seq >= uint64(len(s.transitions)) {
		return Transition{}, fmt.Errorf("record: transition %d out of range (len %d)", seq, len(s.transitions))
	}
	return s.transitions[seq], nil
}

// Len implements TransitionStore.
func (s *MemTransitionStore) Len() (uint64, error) {
	return uint64(len(s.transitions)), nil
}

// LifecycleLog is one operator's claim-lifecycle record: a Merkle tree over
// transition facts, with per-claim monotonic ordering enforced on admission.
// Like the dialog Log it exports no update, no delete, no merge, and no
// cross-log surface.
type LifecycleLog struct {
	id    Hash
	store TransitionStore
	leafs []Hash
	index map[Hash]uint64                 // transition leaf -> seq
	state map[Hash]TransitionKind         // claim -> furthest kind admitted
	claim map[Hash][]uint64               // claim -> sequences, in order
	kinds map[Hash]map[TransitionKind]int // claim -> kind -> count (adjudication may repeat)
}

// OpenLifecycleLog opens the operator's lifecycle log over s, replaying and
// re-verifying every stored transition through the same admission gates
// Append applies.
func OpenLifecycleLog(operator ed25519.PublicKey, s TransitionStore) (*LifecycleLog, error) {
	if len(operator) != ed25519.PublicKeySize {
		return nil, errors.New("record: operator key is malformed")
	}
	if s == nil {
		return nil, errors.New("record: nil transition store")
	}
	l := &LifecycleLog{
		id:    LifecycleLogID(operator),
		store: s,
		index: make(map[Hash]uint64),
		state: make(map[Hash]TransitionKind),
		claim: make(map[Hash][]uint64),
		kinds: make(map[Hash]map[TransitionKind]int),
	}
	n, err := s.Len()
	if err != nil {
		return nil, fmt.Errorf("record: reading transition store length: %w", err)
	}
	for seq := uint64(0); seq < n; seq++ {
		t, err := s.At(seq)
		if err != nil {
			return nil, fmt.Errorf("record: reading stored transition %d: %w", seq, err)
		}
		if err := l.check(t); err != nil {
			return nil, fmt.Errorf("record: stored transition %d does not re-verify: %w", seq, err)
		}
		l.admit(t)
	}
	return l, nil
}

// check applies the admission gates without mutating state.
func (l *LifecycleLog) check(t Transition) error {
	if t.Log != l.id {
		return errors.New("record: transition is bound to a different lifecycle log")
	}
	if t.Kind < KindFiled || t.Kind > KindSealed {
		return errors.New("record: invalid transition kind")
	}
	if t.Claim == zeroHash {
		return errors.New("record: transition names no claim")
	}
	if t.Exchange == zeroHash {
		return errors.New("record: transition names no exchange")
	}
	if _, dup := l.index[t.ID()]; dup {
		return errors.New("record: transition already appended (duplicate leaf)")
	}
	last, seen := l.state[t.Claim]
	switch {
	case !seen:
		if t.Kind != KindFiled {
			return errors.New("record: a claim's first transition must be its filing")
		}
	case t.Kind == KindFiled:
		return errors.New("record: a claim files exactly once")
	case t.Kind == KindAdjudicated:
		// Adjudication activity may recur (each ruling artifact is a new
		// fact) but never after the claim resolved or sealed.
		if last >= KindResolved {
			return errors.New("record: adjudication after resolution is out of order")
		}
	case t.Kind <= last:
		return errors.New("record: lifecycle transitions are monotonic per claim")
	case t.Kind == KindSealed && last < KindResolved:
		return errors.New("record: a claim seals only after it resolves — a clock never force-seals")
	}
	return nil
}

// admit adds a checked transition to the in-memory state.
func (l *LifecycleLog) admit(t Transition) {
	seq := uint64(len(l.leafs))
	leaf := t.ID()
	l.index[leaf] = seq
	l.leafs = append(l.leafs, leaf)
	l.claim[t.Claim] = append(l.claim[t.Claim], seq)
	if t.Kind > l.state[t.Claim] {
		l.state[t.Claim] = t.Kind
	}
	kc := l.kinds[t.Claim]
	if kc == nil {
		kc = make(map[TransitionKind]int)
		l.kinds[t.Claim] = kc
	}
	kc[t.Kind]++
}

// Append admits t through the same gates replay uses and persists it.
func (l *LifecycleLog) Append(t Transition) (uint64, error) {
	if err := l.check(t); err != nil {
		return 0, err
	}
	if err := l.store.Append(t); err != nil {
		return 0, fmt.Errorf("record: persisting transition: %w", err)
	}
	seq := uint64(len(l.leafs))
	l.admit(t)
	return seq, nil
}

// Checkpoint returns the unsigned checkpoint over the lifecycle tree at UTC
// instant at. It is the SAME Checkpoint type the dialog log uses — a witness
// countersigns both the same way — but its Log field is the lifecycle log's
// identity and verifiers bind it with VerifyAs(operator,
// LifecycleLogID(operator)), so the two logs' checkpoints can never stand in
// for each other.
func (l *LifecycleLog) Checkpoint(at time.Time) Checkpoint {
	size := uint64(len(l.leafs))
	head := l.id
	if size > 0 {
		head = mth(l.leafs)
	}
	return Checkpoint{Log: l.id, Size: size, Head: head, IssuedAt: at}
}

// Prove returns the inclusion proof for the transition at seq.
func (l *LifecycleLog) Prove(seq uint64) (Proof, error) {
	size := uint64(len(l.leafs))
	if seq >= size {
		return Proof{}, fmt.Errorf("record: sequence %d out of range (size %d)", seq, size)
	}
	return Proof{Seq: seq, Path: provePath(seq, l.leafs)}, nil
}

// ProveConsistency returns the consistency proof from `size` to the current
// tree — the witness's extension evidence, identical in shape to the dialog
// log's.
func (l *LifecycleLog) ProveConsistency(size uint64) ([]Hash, error) {
	current := uint64(len(l.leafs))
	if size > current {
		return nil, fmt.Errorf("record: size %d exceeds log size %d", size, current)
	}
	if size == 0 || size == current {
		return []Hash{}, nil
	}
	return proveConsistency(size, l.leafs), nil
}

// Claim returns the sequences of a claim's transitions in log order; the
// empty slice means the log has never seen the claim.
func (l *LifecycleLog) Claim(claim Hash) []uint64 {
	return append([]uint64(nil), l.claim[claim]...)
}

// State returns the furthest lifecycle kind a claim has reached; ok is false
// when the log has never seen the claim. An unresolved claim's DWELL — its
// age past filing — is a readable fact for any scan; it is never a verdict,
// and nothing here closes a claim by clock.
func (l *LifecycleLog) State(claim Hash) (TransitionKind, bool) {
	k, ok := l.state[claim]
	return k, ok
}
