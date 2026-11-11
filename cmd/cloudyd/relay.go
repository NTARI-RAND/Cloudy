package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/identity"

	"github.com/NTARI-RAND/Cloudy/internal/coord"
	"github.com/NTARI-RAND/Cloudy/internal/noderelay"
	"github.com/NTARI-RAND/Cloudy/internal/opcred"
)

// relayConfig is what cloudyd needs to relay its members' nodes (decision
// 0001): the orchestrator, this frontend's operator credential, and the nodes
// it vouches for.
type relayConfig struct {
	Orchestrator string        // orchestrator base URL; empty disables the relay
	OperatorID   string        // the operator slug the credential was enrolled under
	KeysDir      string        // the operator's 7 key-seed files (cloudy-enroll -keys)
	NodesFile    string        // lines of "<node-id> <base64 ed25519 public key>"
	Beat, Poll   time.Duration // roll-up windows; 0 = package defaults
}

// newRelay builds the relay and enrolls the listed nodes, upstream first.
func newRelay(ctx context.Context, cfg relayConfig) (*noderelay.Relay, error) {
	if cfg.OperatorID == "" || cfg.KeysDir == "" {
		return nil, fmt.Errorf("-orchestrator needs -operator-id and -operator-keys")
	}
	ks, err := opcred.LoadKeyset(cfg.KeysDir)
	if err != nil {
		return nil, fmt.Errorf("load operator keys: %w", err)
	}
	signer := opcred.NewTransmissionSigner(cfg.OperatorID, ks)
	operatorAuth := func(req *http.Request) error {
		tx, err := signer.Next()
		if err != nil {
			return err
		}
		req.Header.Set(opcred.OperatorHeaderName, opcred.EncodeOperatorHeader(tx))
		return nil
	}
	r := &noderelay.Relay{
		Upstream:       coord.DialAsOperator(cfg.Orchestrator, operatorAuth),
		UpstreamBeat:   cfg.Beat,
		UpstreamPoll:   cfg.Poll,
		EnrollUpstream: noderelay.EnrollViaOrchestrator(cfg.Orchestrator, operatorAuth),
	}
	if cfg.NodesFile != "" {
		nodes, err := readNodes(cfg.NodesFile)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if err := r.Enroll(ctx, n.id, n.pub); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

type enrolledNode struct {
	id  identity.NodeID
	pub ed25519.PublicKey
}

// readNodes parses the nodes file: one "<node-id> <base64 public key>" per
// line; blank lines and lines starting with # are skipped. It holds machine
// IDs and public keys only — never anything that names a person.
func readNodes(path string) ([]enrolledNode, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open nodes file: %w", err)
	}
	defer f.Close()
	var out []enrolledNode
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"<node-id> <base64 public key>\"", path, line)
		}
		pub, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s:%d: public key must be base64 of %d bytes", path, line, ed25519.PublicKeySize)
		}
		out = append(out, enrolledNode{id: identity.NodeID(fields[0]), pub: pub})
	}
	return out, sc.Err()
}
