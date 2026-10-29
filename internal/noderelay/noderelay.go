// Package noderelay is the frontend half of decision 0001
// (docs/decisions/0001-node-connects-through-its-frontend.md): a member's
// computer talks only to its frontend, and the frontend vouches for it as
// operator and relays its signed messages to the orchestrator.
//
// Relay implements coordinator.Coordinator, so the agent's loop speaks the
// protocol to cloudyd exactly as it would to an orchestrator, and cloudyd
// forwards to any coordinator.Coordinator upstream — SoHoLINK through
// coord.DialAsOperator, or a platform's own orchestrator outside Antare.
//
// What the relay guarantees:
//
//   - Only enrolled nodes are relayed. Every signed message is verified
//     against the node's enrolled key before it leaves; a forged or unknown
//     one is refused here and never reaches the orchestrator under the
//     operator's credential.
//   - Messages are forwarded unchanged. The node's signature still verifies
//     at the orchestrator, so the frontend cannot alter what a node said.
//   - The orchestrator sees no persons. Node messages carry a machine ID,
//     capacity and job results only (protocol: "persons never on the wire");
//     member data stays in the frontend.
//   - Traffic is rolled up. Heartbeats reach the orchestrator at most once per
//     UpstreamBeat per node, and polls at most once per UpstreamPoll per node,
//     so the orchestrator's load grows with frontends, not with prosumers.
//     Listings, declines and reports are always forwarded.
//
// Requests from nodes are authenticated by Handler (see auth.go), which binds
// the caller to the node it names, as SPEC §2 requires of a coordinator.
package noderelay

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/coordinator"
	"github.com/NTARI-RAND/sohocloud-protocol/employment"
	"github.com/NTARI-RAND/sohocloud-protocol/fees"
	"github.com/NTARI-RAND/sohocloud-protocol/identity"
	"github.com/NTARI-RAND/sohocloud-protocol/listing"
	"github.com/NTARI-RAND/sohocloud-protocol/liveness"
)

var (
	// ErrUnknownNode: the node has not been enrolled with this frontend.
	ErrUnknownNode = errors.New("noderelay: node not enrolled with this frontend")
	// ErrBadSignature: the message does not verify against the node's key.
	ErrBadSignature = errors.New("noderelay: message signature does not verify")
	// ErrStaleSeq: the Seq does not increase (SPEC §5.5); refused locally so a
	// replay is never absorbed into the roll-up.
	ErrStaleSeq = errors.New("noderelay: Seq does not increase")
	// ErrKeyConflict: a different key is already enrolled for the node.
	ErrKeyConflict = errors.New("noderelay: a different key is already enrolled for this node")
)

// Defaults for the roll-up windows.
const (
	DefaultUpstreamBeat = 60 * time.Second
	DefaultUpstreamPoll = 30 * time.Second
)

type nodeState struct {
	pub        ed25519.PublicKey
	listSeq    uint64
	beatSeq    uint64
	lastBeatUp time.Time // last heartbeat forwarded upstream
	pollAt     time.Time // last upstream poll
	jobs       []employment.Assignment
	settled    map[string]bool
	lastAuthTS int64 // last accepted request-auth timestamp (auth.go)
}

// Relay relays enrolled nodes' protocol calls to an upstream coordinator.
type Relay struct {
	Upstream     coordinator.Coordinator
	UpstreamBeat time.Duration // 0: DefaultUpstreamBeat
	UpstreamPoll time.Duration // 0: DefaultUpstreamPoll
	Now          func() time.Time

	// EnrollUpstream, when set, registers a newly enrolled node's key with the
	// orchestrator (SoHoLINK: POST /nodes/pubkey, operator-authenticated).
	EnrollUpstream func(ctx context.Context, node identity.NodeID, pub ed25519.PublicKey) error

	mu    sync.Mutex
	nodes map[identity.NodeID]*nodeState
}

var _ coordinator.Coordinator = (*Relay)(nil)

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Relay) beatEvery() time.Duration {
	if r.UpstreamBeat > 0 {
		return r.UpstreamBeat
	}
	return DefaultUpstreamBeat
}

func (r *Relay) pollEvery() time.Duration {
	if r.UpstreamPoll > 0 {
		return r.UpstreamPoll
	}
	return DefaultUpstreamPoll
}

// Enroll admits a node's public key. First write wins: re-enrolling the same
// key is a no-op, a different key is refused (rotation is an operator action,
// never a silent overwrite — the same rule SoHoLINK applies).
func (r *Relay) Enroll(ctx context.Context, node identity.NodeID, pub ed25519.PublicKey) error {
	if node == "" || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("noderelay: enroll needs a node ID and a %d-byte ed25519 key", ed25519.PublicKeySize)
	}
	r.mu.Lock()
	if r.nodes == nil {
		r.nodes = map[identity.NodeID]*nodeState{}
	}
	if st, ok := r.nodes[node]; ok {
		r.mu.Unlock()
		if !st.pub.Equal(pub) {
			return ErrKeyConflict
		}
		return nil
	}
	r.mu.Unlock()
	if r.EnrollUpstream != nil {
		if err := r.EnrollUpstream(ctx, node, pub); err != nil {
			return fmt.Errorf("noderelay: enroll %s upstream: %w", node, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.nodes[node]; !ok {
		r.nodes[node] = &nodeState{pub: append(ed25519.PublicKey(nil), pub...), settled: map[string]bool{}}
	}
	return nil
}

// node returns the enrolled state for id; callers hold r.mu.
func (r *Relay) node(id identity.NodeID) (*nodeState, error) {
	st, ok := r.nodes[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownNode, id)
	}
	return st, nil
}

// SubmitListing verifies and always forwards a listing.
func (r *Relay) SubmitListing(ctx context.Context, l listing.CapabilityListing) error {
	r.mu.Lock()
	st, err := r.node(l.NodeID)
	if err == nil && !l.Verify(st.pub) {
		err = ErrBadSignature
	}
	if err == nil && l.Seq <= st.listSeq {
		err = ErrStaleSeq
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if err := r.Upstream.SubmitListing(ctx, l); err != nil {
		return err
	}
	r.mu.Lock()
	if l.Seq > st.listSeq {
		st.listSeq = l.Seq
	}
	r.mu.Unlock()
	return nil
}

// Heartbeat verifies every heartbeat, and forwards at most one per node per
// UpstreamBeat. An absorbed heartbeat is accepted: the node is alive, and the
// orchestrator hears so on the next forwarded one.
func (r *Relay) Heartbeat(ctx context.Context, h liveness.Heartbeat) error {
	r.mu.Lock()
	st, err := r.node(h.NodeID)
	if err == nil && !h.Verify(st.pub) {
		err = ErrBadSignature
	}
	if err == nil && h.Seq <= st.beatSeq {
		err = ErrStaleSeq
	}
	if err != nil {
		r.mu.Unlock()
		return err
	}
	st.beatSeq = h.Seq
	forward := st.lastBeatUp.IsZero() || r.now().Sub(st.lastBeatUp) >= r.beatEvery()
	r.mu.Unlock()
	if !forward {
		return nil
	}
	if err := r.Upstream.Heartbeat(ctx, h); err != nil {
		return err
	}
	r.mu.Lock()
	st.lastBeatUp = r.now()
	r.mu.Unlock()
	return nil
}

// PollJobs answers from the node's cached assignments, polling upstream at
// most once per UpstreamPoll. Assignments the node has already settled
// through this relay are never handed back.
func (r *Relay) PollJobs(ctx context.Context, id identity.NodeID) ([]employment.Assignment, error) {
	r.mu.Lock()
	st, err := r.node(id)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	fresh := !st.pollAt.IsZero() && r.now().Sub(st.pollAt) < r.pollEvery()
	r.mu.Unlock()

	if !fresh {
		jobs, err := r.Upstream.PollJobs(ctx, id)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		st.jobs, st.pollAt = jobs, r.now()
		// Forget settled jobs the orchestrator no longer offers, so the set
		// stays as small as the node's open work.
		offered := make(map[string]bool, len(jobs))
		for _, a := range jobs {
			offered[a.JobID] = true
		}
		for id := range st.settled {
			if !offered[id] {
				delete(st.settled, id)
			}
		}
		r.mu.Unlock()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]employment.Assignment, 0, len(st.jobs))
	for _, a := range st.jobs {
		if !st.settled[a.JobID] {
			out = append(out, a)
		}
	}
	return out, nil
}

// Decline verifies and always forwards.
func (r *Relay) Decline(ctx context.Context, d employment.Decline) error {
	r.mu.Lock()
	st, err := r.node(d.NodeID)
	if err == nil && !d.Verify(st.pub) {
		err = ErrBadSignature
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if err := r.Upstream.Decline(ctx, d); err != nil {
		return err
	}
	r.settle(st, d.JobID)
	return nil
}

// ReportJob verifies and always forwards.
func (r *Relay) ReportJob(ctx context.Context, rep employment.JobReport) error {
	r.mu.Lock()
	st, err := r.node(rep.NodeID)
	if err == nil && !rep.Verify(st.pub) {
		err = ErrBadSignature
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if err := r.Upstream.ReportJob(ctx, rep); err != nil {
		return err
	}
	r.settle(st, rep.JobID)
	return nil
}

func (r *Relay) settle(st *nodeState, job string) {
	r.mu.Lock()
	st.settled[job] = true
	r.mu.Unlock()
}

// Fees forwards the orchestrator's signed fee declaration; it names no node.
func (r *Relay) Fees(ctx context.Context) (fees.FeeDeclaration, error) {
	return r.Upstream.Fees(ctx)
}
