package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/opcred"
)

func TestReadNodes(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b64 := base64.StdEncoding.EncodeToString(pub)
	path := filepath.Join(t.TempDir(), "nodes")
	good := "# enrolled nodes\n\nnode-1 " + b64 + "\n  node-2   " + b64 + "  \n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes, err := readNodes(path)
	if err != nil || len(nodes) != 2 || nodes[1].id != "node-2" || !nodes[1].pub.Equal(pub) {
		t.Fatalf("readNodes = %+v, %v", nodes, err)
	}
	for _, bad := range []string{"node-1\n", "node-1 not-base64!\n", "node-1 " + b64 + " extra\n", "node-1 AAAA\n"} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readNodes(path); err == nil {
			t.Errorf("readNodes accepted %q", strings.TrimSpace(bad))
		}
	}
}

// newRelay loads the operator keyset, enrolls the listed nodes with the
// orchestrator under the operator credential, and refuses to start without one.
func TestNewRelayEnrollsUnderOperatorCredential(t *testing.T) {
	dir := t.TempDir()
	ks, err := opcred.GenerateKeyset()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Save(dir); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	nodes := filepath.Join(t.TempDir(), "nodes")
	if err := os.WriteFile(nodes, []byte("node-1 "+base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var enrolled []string
	orch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(opcred.OperatorHeaderName) == "" {
			t.Error("orchestrator call without the operator credential")
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		enrolled = append(enrolled, r.URL.Path+" "+body["node_id"])
		mu.Unlock()
	}))
	defer orch.Close()

	cfg := relayConfig{Orchestrator: orch.URL, OperatorID: "cloudy", KeysDir: dir, NodesFile: nodes}
	if _, err := newRelay(context.Background(), cfg); err != nil {
		t.Fatalf("newRelay: %v", err)
	}
	if len(enrolled) != 1 || enrolled[0] != "/nodes/pubkey node-1" {
		t.Errorf("enrollments = %v, want node-1 at /nodes/pubkey", enrolled)
	}
	cfg.KeysDir = ""
	if _, err := newRelay(context.Background(), cfg); err == nil {
		t.Error("newRelay started without an operator credential")
	}
}
