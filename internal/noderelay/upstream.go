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
// node's public key with a SoHoLINK-style orchestrator (POST /nodes/pubkey),
// authenticated by decorate — the operator credential. The orchestrator keeps
// the first key it is given for a node; a different key is refused there too.
// The body carries a node ID and a public key only: no person.
func EnrollViaOrchestrator(baseURL string, decorate func(*http.Request) error) func(context.Context, identity.NodeID, ed25519.PublicKey) error {
	client := &http.Client{Timeout: 30 * time.Second}
	return func(ctx context.Context, node identity.NodeID, pub ed25519.PublicKey) error {
		body, err := json.Marshal(map[string]string{
			"node_id":    string(node),
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"algo":       "ed25519",
		})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/nodes/pubkey", bytes.NewReader(body))
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
