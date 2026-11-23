package noderelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/identity"
)

// EnrollViaOrchestrator returns an EnrollUpstream function that registers a
// node with a SoHoLINK-style orchestrator (POST /operators/nodes), authenticated
// by decorate — the operator credential. The orchestrator creates the node as
// this operator's, with no person attached, and enrolls its key in the same
// step; repeating the same node and key is harmless. The body carries a node
// ID and a public key only: no person. The node ID must be a lowercase UUID
// (ValidNodeID); anything else is refused here, before any network call.
// A 409 means the orchestrator already holds this node with a different key,
// or under another owner: either way nothing changed there (ErrKeyConflict).
func EnrollViaOrchestrator(baseURL string, decorate func(*http.Request) error) func(context.Context, identity.NodeID, ed25519.PublicKey) error {
	client := &http.Client{Timeout: 30 * time.Second}
	return func(ctx context.Context, node identity.NodeID, pub ed25519.PublicKey) error {
		if !ValidNodeID(node) {
			return fmt.Errorf("node ID %q is not a lowercase UUID; the orchestrator registers nodes by UUID", node)
		}
		body, err := json.Marshal(map[string]string{
			"node_id":    string(node),
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"algo":       "ed25519",
		})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/operators/nodes", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if decorate != nil {
			if err := decorate(req); err != nil {
				return err
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusConflict:
			return ErrKeyConflict
		case resp.StatusCode < 200 || resp.StatusCode >= 300:
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("orchestrator refused key enrollment: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		return nil
	}
}
