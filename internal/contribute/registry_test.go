package contribute

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// --- test doubles ---

type fakeExec struct {
	kind    WorkloadKind
	preempt bool
	run     func(context.Context, AssignedJob) (Result, error)
}

func (f fakeExec) Kind() WorkloadKind { return f.kind }
func (f fakeExec) Preemptible() bool  { return f.preempt }
func (f fakeExec) Run(ctx context.Context, j AssignedJob) (Result, error) {
	if f.run != nil {
		return f.run(ctx, j)
	}
	return Result{JobID: j.ID, OK: true}, nil
}

type fakeSvc struct {
	healthy bool
	serve   func(context.Context, AssignedJob) error
}

func (f fakeSvc) Kind() WorkloadKind { return Service }
func (f fakeSvc) Healthy() bool      { return f.healthy }
func (f fakeSvc) Serve(ctx context.Context, j AssignedJob) error {
	if f.serve != nil {
		return f.serve(ctx, j)
	}
	<-ctx.Done()
	return ctx.Err()
}

// --- tests ---

func mustRegistry(t *testing.T, c NodeContract) *Registry {
	t.Helper()
	r, err := NewRegistry(c)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestNewRegistryRejectsBadContract(t *testing.T) {
	if _, err := NewRegistry(NodeContract{Placement: Scavenged, Kinds: []WorkloadKind{Service}}); !errors.Is(err, ErrServiceNeedsPinned) {
		t.Fatalf("want ErrServiceNeedsPinned, got %v", err)
	}
}

func TestRegisterContractAndPreemption(t *testing.T) {
	// Scavenged node must reject a non-preemptible executor.
	sc := mustRegistry(t, NodeContract{Placement: Scavenged, Kinds: []WorkloadKind{Compute}})
	if err := sc.Register(fakeExec{kind: Compute, preempt: false}); !errors.Is(err, ErrScavengedNotPreemptible) {
		t.Fatalf("scavenged + non-preemptible: want ErrScavengedNotPreemptible, got %v", err)
	}
	if err := sc.Register(fakeExec{kind: Compute, preempt: true}); err != nil {
		t.Fatalf("scavenged + preemptible should register: %v", err)
	}
	// Duplicate.
	if err := sc.Register(fakeExec{kind: Compute, preempt: true}); !errors.Is(err, ErrDuplicateExecutor) {
		t.Fatalf("want ErrDuplicateExecutor, got %v", err)
	}
	// Uncontracted kind.
	if err := sc.Register(fakeExec{kind: Storage, preempt: true}); !errors.Is(err, ErrKindNotContracted) {
		t.Fatalf("want ErrKindNotContracted, got %v", err)
	}
	// Service via Register is the wrong door.
	if err := sc.Register(fakeExec{kind: Service, preempt: true}); !errors.Is(err, ErrUseRegisterService) {
		t.Fatalf("want ErrUseRegisterService, got %v", err)
	}
	// Pinned node accepts a non-preemptible executor (dedicated capacity).
	pin := mustRegistry(t, NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Compute}})
	if err := pin.Register(fakeExec{kind: Compute, preempt: false}); err != nil {
		t.Fatalf("pinned + non-preemptible should register: %v", err)
	}
}

func TestRegisterService(t *testing.T) {
	pin := mustRegistry(t, NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Service}})
	if err := pin.RegisterService(fakeSvc{}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	if err := pin.RegisterService(fakeSvc{}); !errors.Is(err, ErrDuplicateExecutor) {
		t.Fatalf("second service: want ErrDuplicateExecutor, got %v", err)
	}
	// A registry whose contract omits Service refuses one.
	noSvc := mustRegistry(t, NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Compute}})
	if err := noSvc.RegisterService(fakeSvc{}); !errors.Is(err, ErrKindNotContracted) {
		t.Fatalf("want ErrKindNotContracted, got %v", err)
	}
}

func TestCapabilitiesSortedAndScoped(t *testing.T) {
	r := mustRegistry(t, NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Storage, Compute, Service}})
	if got := r.Capabilities(); len(got) != 0 {
		t.Fatalf("empty registry should advertise nothing, got %v", got)
	}
	if err := r.Register(fakeExec{kind: Storage, preempt: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(fakeExec{kind: Compute, preempt: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterService(fakeSvc{}); err != nil {
		t.Fatal(err)
	}
	want := []WorkloadKind{Compute, Storage, Service} // sorted by iota order
	if got := r.Capabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Capabilities() = %v, want %v", got, want)
	}
}

func TestDispatch(t *testing.T) {
	r := mustRegistry(t, NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Compute, Storage}})
	if err := r.Register(fakeExec{kind: Compute, preempt: true, run: func(_ context.Context, j AssignedJob) (Result, error) {
		return Result{JobID: j.ID, OK: true, Output: j.Payload}, nil
	}}); err != nil {
		t.Fatal(err)
	}

	// Routes to the right executor and returns its result.
	res, err := r.Dispatch(context.Background(), AssignedJob{ID: "j1", Kind: Compute, Payload: []byte("hi")})
	if err != nil || !res.OK || string(res.Output) != "hi" {
		t.Fatalf("dispatch compute: res=%+v err=%v", res, err)
	}

	// Contracted kind but no executor registered.
	if _, err := r.Dispatch(context.Background(), AssignedJob{ID: "j2", Kind: Storage}); !errors.Is(err, ErrNoExecutor) {
		t.Fatalf("want ErrNoExecutor, got %v", err)
	}

	// Uncontracted kind refused before any executor runs.
	if _, err := r.Dispatch(context.Background(), AssignedJob{ID: "j3", Kind: Print}); !errors.Is(err, ErrKindNotContracted) {
		t.Fatalf("want ErrKindNotContracted, got %v", err)
	}
}

func TestServiceServeHonorsContext(t *testing.T) {
	r := mustRegistry(t, NodeContract{Placement: Pinned, Kinds: []WorkloadKind{Service}})
	if err := r.RegisterService(fakeSvc{}); err != nil {
		t.Fatal(err)
	}
	svc, ok := r.Service()
	if !ok {
		t.Fatal("Service() should report the registered service")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Serve(ctx, AssignedJob{ID: "svc", Kind: Service}) }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve should return context.Canceled, got %v", err)
	}
}
