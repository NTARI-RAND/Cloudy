package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NTARI-RAND/sohocloud-protocol/identity"

	"github.com/NTARI-RAND/Cloudy/internal/noderelay"
)

func TestResolveNodeID(t *testing.T) {
	dir := t.TempDir()
	idFile := filepath.Join(dir, "cloudy-node.id")

	// Local modes talk to no orchestrator: no file is created.
	if id, err := resolveNodeID("", idFile, false); err != nil || id != "cloudy-node-0" {
		t.Errorf("local default = %q, %v", id, err)
	}
	if _, err := os.Stat(idFile); err == nil {
		t.Error("a local run created a node ID file")
	}

	// With a coordinator: a UUID is created once and kept.
	first, err := resolveNodeID("", idFile, true)
	if err != nil || !noderelay.ValidNodeID(identity.NodeID(first)) {
		t.Fatalf("coordinator default = %q, %v; want a fresh UUID", first, err)
	}
	if again, err := resolveNodeID("", idFile, true); err != nil || again != first {
		t.Errorf("restart = %q, %v; want the same %q", again, err, first)
	}

	// An explicit -node wins, but must be a UUID with a coordinator.
	const explicit = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	if id, err := resolveNodeID(explicit, idFile, true); err != nil || id != explicit {
		t.Errorf("explicit UUID = %q, %v", id, err)
	}
	if _, err := resolveNodeID("cloudy-node-0", idFile, true); err == nil {
		t.Error("a short -node name was accepted with a coordinator")
	}
}
