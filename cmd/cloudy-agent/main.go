// Command cloudy-agent is the contributor daemon a Cloudy member runs on a
// machine that contributes capacity. It is the home the SoHoLINK internal/agent
// code moves into (executor, allowlist, opt-out, printers, hardware sampling,
// heartbeat, telemetry) — but built around the contribute seam so the runtime
// implementations (Docker, gopsutil, an Android storage provider, GPU) are
// pluggable Executors, not the definition.
//
// This entrypoint is honest about what it is today: the seam and control loop
// are real and tested; the registered executors are a real Storage node (over
// internal/storage's proof-of-possession), a placeholder Compute echo standing
// in for the Docker executor, and a demo presence Service. The Docker/gopsutil/
// spiffe port and the agent->cloudyd->/v0 relay are the named next steps; they
// land behind this seam without changing it.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
)

func main() {
	var (
		nodeID   = flag.String("node", "cloudy-node-0", "node identifier")
		pinned   = flag.Bool("pinned", true, "pinned (dedicated) capacity; false = scavenged (idle-first)")
		withSvc  = flag.Bool("service", true, "offer the demo presence service (requires -pinned)")
		selftest = flag.Bool("selftest", true, "run a store->audit->echo self-test and exit")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	placement := contribute.Scavenged
	kinds := []contribute.WorkloadKind{contribute.Compute, contribute.Storage}
	if *pinned {
		placement = contribute.Pinned
		if *withSvc {
			kinds = append(kinds, contribute.Service)
		}
	}

	reg, err := contribute.NewRegistry(contribute.NodeContract{NodeID: *nodeID, Placement: placement, Kinds: kinds})
	if err != nil {
		log.Error("contract invalid", "err", err)
		os.Exit(1)
	}
	if err := reg.Register(echoExecutor{}); err != nil {
		log.Error("register compute", "err", err)
		os.Exit(1)
	}
	if err := reg.Register(newStorageExecutor()); err != nil {
		log.Error("register storage", "err", err)
		os.Exit(1)
	}
	if *pinned && *withSvc {
		if err := reg.RegisterService(&presenceService{}); err != nil {
			log.Error("register service", "err", err)
			os.Exit(1)
		}
	}

	// ownerActive: no real hardware probe yet (that is the gopsutil port);
	// pinned nodes are never gated, so this stub is correct for -pinned.
	agent := NewAgent(reg, func() bool { return false }, log)
	log.Info("cloudy-agent up", "node", *nodeID, "placement", placement.String(), "capabilities", capsToStrings(agent.Capabilities()))

	if *selftest {
		runSelfTest(context.Background(), agent, log)
		return
	}

	// Long-running mode: serve the pinned service until interrupted.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if _, ok := reg.Service(); ok {
		if err := agent.ServeService(ctx, contribute.AssignedJob{ID: "presence-0", Kind: contribute.Service}); err != nil && ctx.Err() == nil {
			log.Error("service failed", "err", err)
			os.Exit(1)
		}
	} else {
		<-ctx.Done()
	}
}

func capsToStrings(ks []contribute.WorkloadKind) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.String()
	}
	return out
}

// runSelfTest exercises the seam end to end: store an opaque shard, prove
// possession, and echo a compute job.
func runSelfTest(ctx context.Context, agent *Agent, log *slog.Logger) {
	shard := []byte("opaque-sealed-shard-bytes-the-node-cannot-read")
	storePayload, _ := json.Marshal(storageOp{Op: "store", ID: "obj-1", Data: base64.StdEncoding.EncodeToString(shard)})
	if res, err := agent.Dispatch(ctx, contribute.AssignedJob{ID: "s1", Kind: contribute.Storage, Payload: storePayload}); err != nil {
		log.Error("store failed", "err", err)
	} else {
		log.Info("store", "ok", res.OK, "detail", res.Detail)
	}

	auditPayload, _ := json.Marshal(storageOp{Op: "audit", ID: "obj-1"})
	if res, err := agent.Dispatch(ctx, contribute.AssignedJob{ID: "s2", Kind: contribute.Storage, Payload: auditPayload}); err != nil {
		log.Error("audit failed", "err", err)
	} else {
		log.Info("audit", "ok", res.OK, "detail", res.Detail)
	}

	if res, err := agent.Dispatch(ctx, contribute.AssignedJob{ID: "c1", Kind: contribute.Compute, Payload: []byte("hello")}); err != nil {
		log.Error("compute failed", "err", err)
	} else {
		log.Info("compute", "ok", res.OK, "output", string(res.Output))
	}

	if svc, ok := agent.reg.Service(); ok {
		sctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		_ = agent.ServeService(sctx, contribute.AssignedJob{ID: "svc-1", Kind: contribute.Service})
		log.Info("service healthy after stop", "healthy", svc.Healthy())
	}
}
