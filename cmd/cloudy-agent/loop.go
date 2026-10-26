package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/coordinator"
	"github.com/NTARI-RAND/sohocloud-protocol/employment"
	"github.com/NTARI-RAND/sohocloud-protocol/identity"
	"github.com/NTARI-RAND/sohocloud-protocol/listing"
	"github.com/NTARI-RAND/sohocloud-protocol/liveness"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
)

// Loop is the agent → coordinator loop: it lists the node, heartbeats, polls
// for work, runs what the node accepts through the Agent, and reports or
// declines every assignment. Every call is one the node makes; the coordinator
// never calls the node (SPEC §6, the pull model), so the node needs no open
// port and no stable address (registry ID SUB-no-inbound-requirement).
//
// The loop speaks to any coordinator.Coordinator. Which transport carries it
// in production — direct to the coordinator with the node's own SPIFFE SVID,
// or relayed through cloudyd as the member's operator — is wired in main and
// is a named next step; the loop does not change with it.
//
// Every message the node sends is signed with the node's ed25519 key, so a
// relay carries it without being able to alter it. Assignments are verified
// against the coordinator's key when one is configured; an assignment that
// does not verify is declined, never run.
type Loop struct {
	Agent       *Agent
	Coord       coordinator.Coordinator
	Node        identity.NodeID
	Key         ed25519.PrivateKey
	CoordKey    ed25519.PublicKey // nil: assignments are not verified (logged once)
	Class       listing.ComputeClass
	Capacity    listing.Capacity
	Heartbeat   time.Duration
	Poll        time.Duration
	Now         func() time.Time
	Log         *slog.Logger
	mu          sync.Mutex
	seq         uint64
	listed      string          // capabilities in the last accepted listing
	handled     map[string]bool // job IDs already reported or declined
	warnedNoKey bool
}

func (l *Loop) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

func (l *Loop) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.Default()
}

// nextSeq returns a strictly increasing sequence number (SPEC §5.5). It is
// clock-based so it keeps increasing across restarts, and never repeats or
// goes back even if the clock does.
func (l *Loop) nextSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := uint64(l.now().UnixNano())
	if s <= l.seq {
		s = l.seq + 1
	}
	l.seq = s
	return s
}

func capsKey(ks []contribute.WorkloadKind) string {
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = k.String()
	}
	return strings.Join(parts, ",")
}

// List submits a signed capability listing advertising what the node accepts
// right now. A scavenged node whose owner is active advertises nothing.
func (l *Loop) List(ctx context.Context) error {
	caps := l.Agent.Capabilities()
	var opt listing.WorkloadOptIn
	for _, k := range caps {
		switch k {
		case contribute.Compute:
			opt.Compute = true
		case contribute.Print:
			opt.Print = true
			// Storage has no opt-in flag in the pinned protocol (v0.1.0):
			// the node accepts or declines storage work locally either way.
		}
	}
	cl := listing.CapabilityListing{
		NodeID:   l.Node,
		Class:    l.Class,
		Capacity: l.Capacity,
		OptIn:    opt,
		IssuedAt: l.now(),
		Seq:      l.nextSeq(),
	}
	cl.Sign(l.Key)
	if err := l.Coord.SubmitListing(ctx, cl); err != nil {
		return err
	}
	l.mu.Lock()
	l.listed = capsKey(caps)
	l.mu.Unlock()
	return nil
}

// Beat sends a signed heartbeat, re-listing first if what the node accepts has
// changed since the last listing (the owner came back, or left).
func (l *Loop) Beat(ctx context.Context) error {
	l.mu.Lock()
	stale := l.listed != capsKey(l.Agent.Capabilities())
	l.mu.Unlock()
	if stale {
		if err := l.List(ctx); err != nil {
			return err
		}
	}
	h := liveness.Heartbeat{NodeID: l.Node, SentAt: l.now(), Seq: l.nextSeq()}
	h.Sign(l.Key)
	return l.Coord.Heartbeat(ctx, h)
}

// workloadKinds maps the protocol's JobSpec.Workload to the seam's kinds.
var workloadKinds = map[string]contribute.WorkloadKind{
	"compute": contribute.Compute,
	"storage": contribute.Storage,
	"print":   contribute.Print,
}

// PollOnce pulls the node's assignments and settles each one exactly once:
// run and report it, or decline it with a reason. It returns the first
// transport error; per-job outcomes are reported to the coordinator, not
// returned.
func (l *Loop) PollOnce(ctx context.Context) error {
	jobs, err := l.Coord.PollJobs(ctx, l.Node)
	if err != nil {
		return err
	}
	for _, a := range jobs {
		l.mu.Lock()
		done := l.handled[a.JobID]
		l.mu.Unlock()
		if done {
			continue
		}
		if err := l.settle(ctx, a); err != nil {
			return err
		}
		l.mu.Lock()
		if l.handled == nil {
			l.handled = map[string]bool{}
		}
		l.handled[a.JobID] = true
		l.mu.Unlock()
	}
	return nil
}

func (l *Loop) settle(ctx context.Context, a employment.Assignment) error {
	if a.NodeID != l.Node {
		return l.decline(ctx, a, employment.DeclineLocalPolicy, "assignment names another node")
	}
	if l.CoordKey == nil {
		if !l.warnedNoKey {
			l.log().Warn("no coordinator key configured: assignments are not verified")
			l.warnedNoKey = true
		}
	} else if !a.Verify(l.CoordKey) {
		return l.decline(ctx, a, employment.DeclineLocalPolicy, "assignment signature does not verify")
	}
	kind, ok := workloadKinds[a.Spec.Workload]
	if !ok {
		return l.decline(ctx, a, employment.DeclineLocalPolicy, "unknown workload "+a.Spec.Workload)
	}
	// Opt-out is enforced locally, never on the wire (SPEC §5.1): the node
	// declines what it does not accept, whatever the coordinator sent.
	accepts := false
	for _, k := range l.Agent.Capabilities() {
		if k == kind {
			accepts = true
		}
	}
	if !accepts {
		reason := employment.DeclineLocalPolicy
		if l.Agent.scavengedYield() {
			reason = employment.DeclineUnavailable
		}
		return l.decline(ctx, a, reason, "node does not accept "+kind.String()+" now")
	}

	started := l.now()
	res, err := l.Agent.Dispatch(ctx, contribute.AssignedJob{
		ID:   a.JobID,
		Kind: kind,
		// Stand-in until the Docker executor lands: the job's arguments are
		// the executor's payload.
		Payload: []byte(strings.Join(a.Spec.Args, " ")),
	})
	switch {
	case errors.Is(err, ErrOwnerActive):
		return l.decline(ctx, a, employment.DeclineUnavailable, "owner returned")
	case errors.Is(err, contribute.ErrNoExecutor):
		return l.decline(ctx, a, employment.DeclineLocalPolicy, "no executor for "+kind.String())
	}
	r := employment.JobReport{
		JobID:      a.JobID,
		NodeID:     l.Node,
		StartedAt:  started,
		FinishedAt: l.now(),
	}
	if err != nil {
		r.ExitCode, r.FailureCause = 1, err.Error()
	} else if !res.OK {
		r.ExitCode, r.FailureCause = 1, res.Detail
	}
	r.Sign(l.Key)
	l.log().Info("job settled", "job", a.JobID, "kind", kind.String(), "exit", r.ExitCode)
	return l.Coord.ReportJob(ctx, r)
}

func (l *Loop) decline(ctx context.Context, a employment.Assignment, reason employment.DeclineReason, why string) error {
	d := employment.Decline{JobID: a.JobID, NodeID: l.Node, Reason: reason, DeclinedAt: l.now()}
	d.Sign(l.Key)
	l.log().Info("job declined", "job", a.JobID, "reason", string(reason), "why", why)
	return l.Coord.Decline(ctx, d)
}

// Run lists the node, then heartbeats and polls on their intervals until ctx
// ends. A failed call is logged and retried on the next tick: a node behind a
// flaky home connection keeps going rather than exiting.
func (l *Loop) Run(ctx context.Context) error {
	hb, poll := l.Heartbeat, l.Poll
	if hb <= 0 {
		hb = 30 * time.Second
	}
	if poll <= 0 {
		poll = 10 * time.Second
	}
	if err := l.List(ctx); err != nil {
		l.log().Warn("listing failed; will retry with the next heartbeat", "err", err)
		l.mu.Lock()
		l.listed = "\x00unlisted"
		l.mu.Unlock()
	}
	hbT, pollT := time.NewTicker(hb), time.NewTicker(poll)
	defer hbT.Stop()
	defer pollT.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-hbT.C:
			if err := l.Beat(ctx); err != nil && ctx.Err() == nil {
				l.log().Warn("heartbeat failed", "err", err)
			}
		case <-pollT.C:
			if err := l.PollOnce(ctx); err != nil && ctx.Err() == nil {
				l.log().Warn("poll failed", "err", err)
			}
		}
	}
}
