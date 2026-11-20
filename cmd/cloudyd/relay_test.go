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
	const id1, id2 = "0b6c0b4e-2d4f-4a8e-9f3a-1c2d3e4f5a6b", "7d1e9c2a-5b3f-4e6d-8a1b-2c3d4e5f6a7b"
	good := "# enrolled nodes\n\n" + id1 + " " + b64 + "\n  " + id2 + "   " + b64 + "  \n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes, err := readNodes(path)
	if err != nil || len(nodes) != 2 || nodes[1].id != id2 || !nodes[1].pub.Equal(pub) {
		t.Fatalf("readNodes = %+v, %v", nodes, err)
	}
	for _, bad := range []string{
		id1 + "\n", id1 + " not-base64!\n", id1 + " " + b64 + " extra\n", id1 + " AAAA\n",
		"node-1 " + b64 + "\n",                               // a short name: SoHoLINK registers nodes by UUID
		"0B6C0B4E-2D4F-4A8E-9F3A-1C2D3E4F5A6B " + b64 + "\n", // not lowercase
	} {
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
	if err := os.WriteFile(nodes, []byte("0b6c0b4e-2d4f-4a8e-9f3a-1c2d3e4f5a6b "+base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
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
	if len(enrolled) != 1 || enrolled[0] != "/operators/nodes 0b6c0b4e-2d4f-4a8e-9f3a-1c2d3e4f5a6b" {
		t.Errorf("enrollments = %v, want the node at /operators/nodes", enrolled)
	}
	cfg.KeysDir = ""
	if _, err := newRelay(context.Background(), cfg); err == nil {
		t.Error("newRelay started without an operator credential")
	}
}
