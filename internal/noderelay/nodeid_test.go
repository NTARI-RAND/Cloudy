package noderelay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/NTARI-RAND/sohocloud-protocol/identity"
)

func TestNewNodeID_IsAFreshV4UUID(t *testing.T) {
	seen := map[identity.NodeID]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewNodeID()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidNodeID(id) {
			t.Fatalf("NewNodeID = %q, not a lowercase UUID", id)
		}
		s := string(id)
		if s[14] != '4' || !strings.ContainsRune("89ab", rune(s[19])) {
			t.Errorf("NewNodeID = %q: want version 4, RFC 4122 variant", id)
		}
		if seen[id] {
			t.Fatalf("NewNodeID repeated %q", id)
		}
		seen[id] = true
	}
}

func TestValidNodeID(t *testing.T) {
	for id, want := range map[identity.NodeID]bool{
		"3f2b8c1e-6a4d-4b7e-9c1f-0a2b3c4d5e6f":   true,
		"3F2B8C1E-6A4D-4B7E-9C1F-0A2B3C4D5E6F":   false, // uppercase
		"cloudy-node-0":                          false,
		"":                                       false,
		"3f2b8c1e6a4d4b7e9c1f0a2b3c4d5e6f":       false, // no hyphens
		"3f2b8c1e-6a4d-4b7e-9c1f-0a2b3c4d5e6":    false, // short
		"3f2b8c1e-6a4d-4b7e-9c1f-0a2b3c4d5e6f0":  false, // long
		"3f2b8c1e-6a4d-4b7e-9c1f-0a2b3c4d5e6g":   false, // not hex
		"{3f2b8c1e-6a4d-4b7e-9c1f-0a2b3c4d5e6f}": false,
		"3f2b8c1e6-a4d-4b7e-9c1f-0a2b3c4d5e6f":   false, // right length, hyphen moved
	} {
		if got := ValidNodeID(id); got != want {
			t.Errorf("ValidNodeID(%q) = %v, want %v", id, got, want)
		}
	}
}

// A machine keeps its ID across restarts; the file is owner-only and a
// damaged file is refused rather than silently replaced.
func TestLoadOrCreateNodeID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloudy-node.id")
	first, err := LoadOrCreateNodeID(path)
	if err != nil || !ValidNodeID(first) {
		t.Fatalf("first run = %q, %v", first, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports 0666 for any writable file; the mode check is Unix-only.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("ID file mode = %v; want 0600", info.Mode().Perm())
	}
	again, err := LoadOrCreateNodeID(path)
	if err != nil || again != first {
		t.Fatalf("second run = %q, %v; want the same %q", again, err, first)
	}
	for _, bad := range []string{"cloudy-node-0\n", "", "3F2B8C1E-6A4D-4B7E-9C1F-0A2B3C4D5E6F\n"} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		id, err := LoadOrCreateNodeID(path)
		if err == nil {
			t.Errorf("ID file %q accepted as %q", strings.TrimSpace(bad), id)
		} else if !strings.Contains(err.Error(), "safe to delete") {
			t.Errorf("damaged-file error %q does not say what to do", err)
		}
	}
}

// The orchestrator answers 201 for a new node and 200 for a repeat; both are
// success. A node ID that is not a UUID never leaves this machine.
func TestEnrollViaOrchestrator_StatusesAndIDCheck(t *testing.T) {
	calls := 0
	status := http.StatusCreated
	orch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(status)
		if status == http.StatusConflict {
			w.Write([]byte(`{"error":"node_id is already registered by someone else"}`)) //nolint:errcheck
		}
	}))
	defer orch.Close()
	enroll := EnrollViaOrchestrator(orch.URL, nil)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	id := identity.NodeID("3f2b8c1e-6a4d-4b7e-9c1f-0a2b3c4d5e6f")

	if err := enroll(ctx, id, pub); err != nil {
		t.Errorf("201 Created = %v, want success", err)
	}
	status = http.StatusOK
	if err := enroll(ctx, id, pub); err != nil {
		t.Errorf("200 OK (repeat) = %v, want success", err)
	}
	status = http.StatusBadRequest
	if err := enroll(ctx, id, pub); err == nil {
		t.Error("400 from the orchestrator was treated as success")
	}
	// A 409 keeps the orchestrator's reason: "owned by someone else" must not
	// read as a key mismatch.
	status = http.StatusConflict
	err := enroll(ctx, id, pub)
	if !errors.Is(err, ErrKeyConflict) || !strings.Contains(err.Error(), "registered by someone else") {
		t.Errorf("409 = %v; want ErrKeyConflict carrying the orchestrator's reason", err)
	}
	if err != nil && strings.Contains(err.Error(), `{"error"`) {
		t.Errorf("409 = %v; want the reason as plain text, not raw JSON", err)
	}

	before := calls
	if err := enroll(ctx, "cloudy-node-0", pub); err == nil {
		t.Error("a short node name was accepted")
	}
	if calls != before {
		t.Error("a short node name was sent to the orchestrator")
	}
}

func TestOrchestratorReason(t *testing.T) {
	for body, want := range map[string]string{
		`{"error":"node_id is already registered by someone else"}`: "node_id is already registered by someone else",
		"  plain text reason \n":                                    "plain text reason",
		`{"other":"x"}`:                                             `{"other":"x"}`,
		"":                                                          "",
	} {
		if got := orchestratorReason([]byte(body)); got != want {
			t.Errorf("orchestratorReason(%q) = %q, want %q", body, got, want)
		}
	}
}
