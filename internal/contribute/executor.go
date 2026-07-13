package contribute

import (
	"context"
	"time"
)

// WorkloadKind is what a contributor node can be asked to do. It mirrors the
// protocol's listing.WorkloadOptIn (Compute, Print, Storage) and adds Service
// — a long-running workload that is a first-class seam variant, not a batch
// job dressed up as one. The node contract decides which kinds a given machine
// will actually accept.
type WorkloadKind int

const (
	// Compute is a batch job that runs and ends (today's Docker executor).
	Compute WorkloadKind = iota
	// Print shares a local printer (CUPS/USB) for one job.
	Print
	// Storage holds opaque sealed shards and proves possession on demand.
	Storage
	// Service is a long-running, pinned workload (a hosted "outcome") that
	// stays up rather than completing. It requires Pinned placement.
	Service
)

func (k WorkloadKind) String() string {
	switch k {
	case Compute:
		return "compute"
	case Print:
		return "print"
	case Storage:
		return "storage"
	case Service:
		return "service"
	default:
		return "unknown"
	}
}

// Valid reports whether k is one of the defined kinds.
func (k WorkloadKind) Valid() bool { return k >= Compute && k <= Service }

// Placement is the capacity contract between the owner and the network.
type Placement int

const (
	// Scavenged capacity is lent while idle and reclaimed the instant the
	// owner returns. Only preemptible executors may run here.
	Scavenged Placement = iota
	// Pinned capacity is dedicated: declared, not scavenged. Services require
	// it because they cannot yield to the owner mid-flight.
	Pinned
)

func (p Placement) String() string {
	switch p {
	case Scavenged:
		return "scavenged"
	case Pinned:
		return "pinned"
	default:
		return "unknown"
	}
}

// AssignedJob is one accepted unit of work. Payload is opaque to the seam; the
// executor for the job's Kind interprets it. Deadline is advisory (zero means
// none) — enforcement is the executor's, using ctx.
type AssignedJob struct {
	ID       string
	Kind     WorkloadKind
	Payload  []byte
	Deadline time.Time
}

// Result is the outcome of running an AssignedJob. OK false with a nil error
// is a clean negative (e.g. a storage proof that did not verify); a non-nil
// error from Run is an operational failure to run at all.
type Result struct {
	JobID  string
	OK     bool
	Detail string
	Output []byte
}

// Executor runs one accepted one-shot assignment on local resources. This is
// the seam every batch-style contributor implements (Docker compute, printing,
// storage store/audit). Long-running services implement ServiceExecutor
// instead.
type Executor interface {
	// Kind is the single workload kind this executor serves. It must not be
	// Service (services implement ServiceExecutor).
	Kind() WorkloadKind
	// Preemptible reports whether an in-flight run can be paused or stopped
	// when the owner returns. Scavenged nodes require this; the Registry
	// refuses a non-preemptible executor on a scavenged contract.
	Preemptible() bool
	// Run executes the job. It must honor ctx cancellation (that is how the
	// owner-never-interrupted guarantee reaches a running scavenged job).
	Run(ctx context.Context, job AssignedJob) (Result, error)
}

// ServiceExecutor runs a long-running, pinned service. Serve blocks for the
// life of the service; Healthy is a liveness signal the agent can attest.
type ServiceExecutor interface {
	// Kind must return Service.
	Kind() WorkloadKind
	// Healthy reports current liveness (for heartbeat attestation).
	Healthy() bool
	// Serve runs the service until ctx is cancelled or it fails fatally.
	// A clean shutdown on ctx cancellation returns ctx.Err().
	Serve(ctx context.Context, job AssignedJob) error
}
