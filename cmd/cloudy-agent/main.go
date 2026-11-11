// Command cloudy-agent is the contributor daemon a Cloudy member runs on a
// machine that contributes capacity. It is the home the SoHoLINK internal/agent
// code moves into (executor, allowlist, opt-out, printers, hardware sampling,
// heartbeat, telemetry) — but built around the contribute seam so the runtime
// implementations (Docker, gopsutil, an Android storage provider, GPU) are
// pluggable Executors, not the definition.
//
// This entrypoint is honest about what it is today: the seam, the control loop
// and the agent → coordinator loop (loop.go) are real and tested; the
// registered executors are a real Storage node (over internal/storage's
// proof-of-possession), a placeholder Compute echo standing in for the Docker
// executor, and a demo presence Service.
//
// With -coordinator set, the agent lists itself, heartbeats, polls for work and
// reports, over outbound calls only. Per decision 0001 it talks to its
// frontend: point -coordinator at cloudyd, which relays to the orchestrator
// under the frontend's operator credential (internal/noderelay). Every request
// carries the node's request signature, and every message its own signature. The Docker/
// gopsutil port lands behind the executor seam without changing the loop.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/identity"
	"github.com/NTARI-RAND/sohocloud-protocol/listing"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
	"github.com/NTARI-RAND/Cloudy/internal/coord"
	"github.com/NTARI-RAND/Cloudy/internal/noderelay"
)

func main() {
	var (
		nodeID    = flag.String("node", "cloudy-node-0", "node identifier")
		pinned    = flag.Bool("pinned", true, "pinned (dedicated) capacity; false = scavenged (idle-first)")
		withSvc   = flag.Bool("service", true, "offer the demo presence service (requires -pinned)")
		selftest  = flag.Bool("selftest", true, "run a store->audit->echo self-test and exit (ignored with -coordinator)")
		coordURL  = flag.String("coordinator", "", "your frontend's base URL (cloudyd); when set, run the agent → coordinator loop")
		keyPath   = flag.String("node-key", "cloudy-node.key", "node ed25519 key file (hex seed); created with mode 0600 if missing")
		coordPub  = flag.String("coordinator-key", "", "coordinator ed25519 public key (hex); assignments are verified against it")
		class     = flag.String("class", string(listing.ClassStandard), "compute class: micro | standard | server")
		hbEvery   = flag.Duration("heartbeat", 30*time.Second, "heartbeat interval")
		pollEvery = flag.Duration("poll", 10*time.Second, "job poll interval")
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

	if *coordURL != "" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := runLoop(ctx, agent, reg, log, *coordURL, *nodeID, *keyPath, *coordPub, *class, *hbEvery, *pollEvery); err != nil {
			log.Error("coordinator loop", "err", err)
			os.Exit(1)
		}
		return
	}

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

// runLoop runs the agent → coordinator loop until ctx ends, serving the pinned
// service alongside it when there is one.
func runLoop(ctx context.Context, agent *Agent, reg *contribute.Registry, log *slog.Logger,
	coordURL, nodeID, keyPath, coordPubHex, class string, hb, poll time.Duration) error {
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return err
	}
	var coordKey ed25519.PublicKey
	if coordPubHex != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(coordPubHex))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("-coordinator-key: want %d bytes of hex", ed25519.PublicKeySize)
		}
		coordKey = raw
	}
	switch listing.ComputeClass(class) {
	case listing.ClassMicro, listing.ClassStandard, listing.ClassServer:
	default:
		return fmt.Errorf("-class %q: want micro, standard or server", class)
	}
	log.Info("node key ready; your frontend must enroll this public key",
		"node", nodeID, "public_key", base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))

	if _, ok := reg.Service(); ok {
		go func() {
			if err := agent.ServeService(ctx, contribute.AssignedJob{ID: "presence-0", Kind: contribute.Service}); err != nil && ctx.Err() == nil {
				log.Error("service failed", "err", err)
			}
		}()
	}
	l := &Loop{
		Agent: agent, Coord: coord.DialWith(coordURL, noderelay.NodeAuth(identity.NodeID(nodeID), key, nil)),
		Node: identity.NodeID(nodeID),
		Key:  key, CoordKey: coordKey, Class: listing.ComputeClass(class),
		Heartbeat: hb, Poll: poll, Log: log,
	}
	if err := l.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// loadOrCreateKey reads the node's ed25519 seed (hex) from path, creating it
// with owner-only permissions on first run. The private key never leaves this
// machine; only signatures and the public key do.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		seed := hex.EncodeToString(priv.Seed()) + "\n"
		if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
			return nil, fmt.Errorf("write node key: %w", err)
		}
		return priv, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read node key: %w", err)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("node key %s is readable by others (mode %o); chmod 600 it", path, info.Mode().Perm())
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("node key %s: want a %d-byte hex seed", path, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
