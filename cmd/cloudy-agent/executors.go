package main

import (
	"context"
	"sync"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
)

// echoExecutor is a minimal, dependency-free Compute executor: it returns its
// payload. It stands in for the Docker compute executor (the heavy port that
// satisfies this same seam next) so the Compute route is proven without
// dragging the docker toolchain into the module yet. Preemptible.
type echoExecutor struct{}

func (echoExecutor) Kind() contribute.WorkloadKind { return contribute.Compute }
func (echoExecutor) Preemptible() bool             { return true }
func (echoExecutor) Run(_ context.Context, job contribute.AssignedJob) (contribute.Result, error) {
	return contribute.Result{JobID: job.ID, OK: true, Detail: "echo", Output: job.Payload}, nil
}

// presenceService is a demo long-running Service: it reports healthy for its
// lifetime and shuts down cleanly when the context is cancelled. It exists to
// prove the ServiceExecutor half of the seam and the pinned-capacity contract;
// a real hosted service (a site, a store, a game server) implements the same
// interface.
type presenceService struct {
	mu      sync.Mutex
	healthy bool
}

func (p *presenceService) Kind() contribute.WorkloadKind { return contribute.Service }

func (p *presenceService) Healthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.healthy
}

func (p *presenceService) Serve(ctx context.Context, _ contribute.AssignedJob) error {
	p.mu.Lock()
	p.healthy = true
	p.mu.Unlock()
	<-ctx.Done()
	p.mu.Lock()
	p.healthy = false
	p.mu.Unlock()
	return ctx.Err()
}
