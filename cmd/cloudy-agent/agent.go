package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
)

// ErrOwnerActive is returned when scavenged work is refused because the owner
// has returned. It is a deferral, not a failure.
var ErrOwnerActive = errors.New("cloudy-agent: owner active; scavenged work deferred")

// Agent is the contributor daemon's control loop over the contribute seam. It
// owns the owner-never-interrupted gate: on a scavenged node it stops
// advertising and dispatching work while the owner is active. On a pinned node
// the owner signal does not gate anything — the capacity is dedicated.
//
// This is the seam-side skeleton the migrated SoHoLINK agent plugs into: the
// heartbeat/opt-out/telemetry loop calls Capabilities and Dispatch, and the
// Docker/gopsutil/spiffe code lands as Executor implementations and a real
// ownerActive probe, not as changes here.
type Agent struct {
	reg         *contribute.Registry
	ownerActive func() bool
	log         *slog.Logger
}

// NewAgent builds an agent. ownerActive reports whether the machine's owner is
// currently using it (nil means "never active", e.g. a headless pinned box).
func NewAgent(reg *contribute.Registry, ownerActive func() bool, log *slog.Logger) *Agent {
	if ownerActive == nil {
		ownerActive = func() bool { return false }
	}
	if log == nil {
		log = slog.Default()
	}
	return &Agent{reg: reg, ownerActive: ownerActive, log: log}
}

// scavengedYield reports whether the owner gate is currently closing this node
// to scavenged work.
func (a *Agent) scavengedYield() bool {
	return a.reg.Contract().Placement == contribute.Scavenged && a.ownerActive()
}

// Capabilities is what the agent advertises upstream this heartbeat. A
// scavenged node advertises nothing while the owner is active — it has yielded
// the machine entirely.
func (a *Agent) Capabilities() []contribute.WorkloadKind {
	if a.scavengedYield() {
		return nil
	}
	return a.reg.Capabilities()
}

// Dispatch runs a one-shot job, refusing scavenged work while the owner is
// active (ErrOwnerActive).
func (a *Agent) Dispatch(ctx context.Context, job contribute.AssignedJob) (contribute.Result, error) {
	if a.scavengedYield() {
		return contribute.Result{JobID: job.ID, OK: false, Detail: "owner active"}, ErrOwnerActive
	}
	return a.reg.Dispatch(ctx, job)
}

// ServeService runs the node's pinned service (if any) until ctx is cancelled.
// Services run on pinned capacity, so the owner gate does not apply.
func (a *Agent) ServeService(ctx context.Context, job contribute.AssignedJob) error {
	svc, ok := a.reg.Service()
	if !ok {
		return contribute.ErrNoExecutor
	}
	a.log.Info("service starting", "node", a.reg.Contract().NodeID, "job", job.ID)
	err := svc.Serve(ctx, job)
	a.log.Info("service stopped", "node", a.reg.Contract().NodeID, "job", job.ID, "err", err)
	return err
}
