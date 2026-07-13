package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
)

func pinnedAgent(t *testing.T, ownerActive func() bool) *Agent {
	t.Helper()
	reg, err := contribute.NewRegistry(contribute.NodeContract{
		NodeID: "test", Placement: contribute.Pinned,
		Kinds: []contribute.WorkloadKind{contribute.Compute, contribute.Storage, contribute.Service},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(echoExecutor{}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(newStorageExecutor()); err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterService(&presenceService{}); err != nil {
		t.Fatal(err)
	}
	return NewAgent(reg, ownerActive, nil)
}

func TestStorageStoreThenAuditProvesPossession(t *testing.T) {
	agent := pinnedAgent(t, nil)
	shard := []byte("opaque sealed bytes the host can never read but can prove it holds")

	store, _ := json.Marshal(storageOp{Op: "store", ID: "o1", Data: base64.StdEncoding.EncodeToString(shard)})
	res, err := agent.Dispatch(context.Background(), contribute.AssignedJob{ID: "s1", Kind: contribute.Storage, Payload: store})
	if err != nil || !res.OK {
		t.Fatalf("store: res=%+v err=%v", res, err)
	}

	audit, _ := json.Marshal(storageOp{Op: "audit", ID: "o1"})
	res, err = agent.Dispatch(context.Background(), contribute.AssignedJob{ID: "s2", Kind: contribute.Storage, Payload: audit})
	if err != nil || !res.OK {
		t.Fatalf("audit should prove possession: res=%+v err=%v", res, err)
	}

	// Auditing an unknown shard fails.
	missing, _ := json.Marshal(storageOp{Op: "audit", ID: "nope"})
	if _, err := agent.Dispatch(context.Background(), contribute.AssignedJob{ID: "s3", Kind: contribute.Storage, Payload: missing}); err == nil {
		t.Fatal("audit of missing shard should error")
	}
}

func TestComputeEchoRoutes(t *testing.T) {
	agent := pinnedAgent(t, nil)
	res, err := agent.Dispatch(context.Background(), contribute.AssignedJob{ID: "c1", Kind: contribute.Compute, Payload: []byte("ping")})
	if err != nil || !res.OK || string(res.Output) != "ping" {
		t.Fatalf("compute echo: res=%+v err=%v", res, err)
	}
}

func TestPinnedNodeIgnoresOwnerGate(t *testing.T) {
	agent := pinnedAgent(t, func() bool { return true }) // owner "active"
	// Pinned capacity is dedicated: owner activity does not reduce it.
	if caps := agent.Capabilities(); len(caps) != 3 {
		t.Fatalf("pinned node should advertise all 3 kinds regardless of owner, got %v", caps)
	}
	if _, err := agent.Dispatch(context.Background(), contribute.AssignedJob{ID: "c1", Kind: contribute.Compute, Payload: []byte("x")}); err != nil {
		t.Fatalf("pinned dispatch should not be gated: %v", err)
	}
}

func TestScavengedNodeYieldsToOwner(t *testing.T) {
	reg, err := contribute.NewRegistry(contribute.NodeContract{
		NodeID: "laptop", Placement: contribute.Scavenged,
		Kinds: []contribute.WorkloadKind{contribute.Compute, contribute.Storage},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(echoExecutor{}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(newStorageExecutor()); err != nil {
		t.Fatal(err)
	}

	active := true
	agent := NewAgent(reg, func() bool { return active }, nil)

	// Owner present: advertise nothing, refuse work.
	if caps := agent.Capabilities(); caps != nil {
		t.Fatalf("scavenged node with owner active should advertise nothing, got %v", caps)
	}
	if _, err := agent.Dispatch(context.Background(), contribute.AssignedJob{ID: "c1", Kind: contribute.Compute, Payload: []byte("x")}); !errors.Is(err, ErrOwnerActive) {
		t.Fatalf("want ErrOwnerActive, got %v", err)
	}

	// Owner leaves: capacity returns.
	active = false
	if caps := agent.Capabilities(); len(caps) != 2 {
		t.Fatalf("scavenged node with owner away should advertise 2 kinds, got %v", caps)
	}
	if res, err := agent.Dispatch(context.Background(), contribute.AssignedJob{ID: "c2", Kind: contribute.Compute, Payload: []byte("go")}); err != nil || !res.OK {
		t.Fatalf("dispatch after owner leaves: res=%+v err=%v", res, err)
	}
}

func TestServiceLifecycle(t *testing.T) {
	agent := pinnedAgent(t, nil)
	svc, ok := agent.reg.Service()
	if !ok {
		t.Fatal("expected a registered service")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.ServeService(ctx, contribute.AssignedJob{ID: "svc", Kind: contribute.Service}) }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("service should stop cleanly on cancel, got %v", err)
	}
	if svc.Healthy() {
		t.Error("service should report unhealthy after shutdown")
	}
}
