package contribute

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

var (
	// ErrKindNotContracted means an executor or job kind is outside the node
	// contract.
	ErrKindNotContracted = errors.New("contribute: workload kind not in node contract")
	// ErrScavengedNotPreemptible means a non-preemptible executor was offered
	// to a scavenged node, which would break the owner-never-interrupted
	// guarantee.
	ErrScavengedNotPreemptible = errors.New("contribute: scavenged node requires a preemptible executor")
	// ErrDuplicateExecutor means a kind already has a registered executor.
	ErrDuplicateExecutor = errors.New("contribute: executor already registered for kind")
	// ErrUseRegisterService means a Service-kind executor was passed to
	// Register instead of RegisterService.
	ErrUseRegisterService = errors.New("contribute: service kind must be registered with RegisterService")
	// ErrNotService means a ServiceExecutor did not report Kind()==Service.
	ErrNotService = errors.New("contribute: service executor must report Kind()==Service")
	// ErrNoExecutor means no executor is registered for a dispatched kind.
	ErrNoExecutor = errors.New("contribute: no executor registered for kind")
)

// Registry binds a node's contract to the concrete executors that satisfy it.
// It is the one place the contract's rules (contracted kinds only; scavenged
// requires preemptible; service requires pinned) are enforced at registration
// time, so a misconfiguration fails at startup rather than mid-assignment.
type Registry struct {
	contract NodeContract
	batch    map[WorkloadKind]Executor
	service  ServiceExecutor
}

// NewRegistry validates the contract and returns an empty registry for it.
func NewRegistry(c NodeContract) (*Registry, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Registry{contract: c, batch: make(map[WorkloadKind]Executor)}, nil
}

// Register adds a one-shot executor. It rejects the Service kind (use
// RegisterService), kinds outside the contract, non-preemptible executors on
// scavenged capacity, and a second executor for a kind already served.
func (r *Registry) Register(e Executor) error {
	k := e.Kind()
	if k == Service {
		return ErrUseRegisterService
	}
	if !k.Valid() {
		return fmt.Errorf("contribute: invalid kind %d", int(k))
	}
	if !r.contract.Allows(k) {
		return fmt.Errorf("%w: %s", ErrKindNotContracted, k)
	}
	if r.contract.Placement == Scavenged && !e.Preemptible() {
		return fmt.Errorf("%w: %s", ErrScavengedNotPreemptible, k)
	}
	if _, dup := r.batch[k]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicateExecutor, k)
	}
	r.batch[k] = e
	return nil
}

// RegisterService adds the node's long-running service. The contract must
// permit Service (which, by NodeContract.Validate, guarantees Pinned
// placement), and only one service may be registered.
func (r *Registry) RegisterService(s ServiceExecutor) error {
	if s.Kind() != Service {
		return ErrNotService
	}
	if !r.contract.Allows(Service) {
		return fmt.Errorf("%w: %s", ErrKindNotContracted, Service)
	}
	if r.service != nil {
		return fmt.Errorf("%w: %s", ErrDuplicateExecutor, Service)
	}
	r.service = s
	return nil
}

// Capabilities returns the sorted kinds actually registered (and therefore
// permitted by the contract). This is what the agent advertises upstream —
// never more than the node truly serves.
func (r *Registry) Capabilities() []WorkloadKind {
	out := make([]WorkloadKind, 0, len(r.batch)+1)
	for k := range r.batch {
		out = append(out, k)
	}
	if r.service != nil {
		out = append(out, Service)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Dispatch routes a one-shot job to its executor. It refuses jobs outside the
// contract or with no registered executor before any work runs.
func (r *Registry) Dispatch(ctx context.Context, job AssignedJob) (Result, error) {
	if !r.contract.Allows(job.Kind) {
		return Result{JobID: job.ID}, fmt.Errorf("%w: %s", ErrKindNotContracted, job.Kind)
	}
	e, ok := r.batch[job.Kind]
	if !ok {
		return Result{JobID: job.ID}, fmt.Errorf("%w: %s", ErrNoExecutor, job.Kind)
	}
	return e.Run(ctx, job)
}

// Service returns the registered service executor, if any.
func (r *Registry) Service() (ServiceExecutor, bool) {
	return r.service, r.service != nil
}

// Contract returns the node contract this registry enforces.
func (r *Registry) Contract() NodeContract { return r.contract }
