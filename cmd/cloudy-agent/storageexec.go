package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
	"github.com/NTARI-RAND/Cloudy/internal/storage"
)

// storageExecutor is a real Storage-kind executor behind the contribute seam.
// It holds OPAQUE sealed shards — it can never read them, because the member
// seals client-side before the bytes ever leave the device (the zero-knowledge
// storage-privacy design). On an "audit" it proves it still holds the exact
// bytes using the proof-of-possession challenge/response in internal/storage,
// without learning anything about the content.
//
// Preemptible: yes. Holding bytes survives a pause, and the agent stops
// serving reads while the owner is active. (Durability across a real
// preemption needs on-disk persistence — the in-memory map here is the seam
// proof; persistence is the same follow-up the Drops log has.)
type storageExecutor struct {
	mu     sync.Mutex
	shards map[string][]byte
	audits int
}

func newStorageExecutor() *storageExecutor {
	return &storageExecutor{shards: make(map[string][]byte), audits: 8}
}

func (s *storageExecutor) Kind() contribute.WorkloadKind { return contribute.Storage }
func (s *storageExecutor) Preemptible() bool             { return true }

// storageOp is the opaque job payload the seam hands this executor.
type storageOp struct {
	Op   string `json:"op"`                 // "store" | "audit"
	ID   string `json:"id"`                 // shard identifier
	Data string `json:"data_b64,omitempty"` // opaque sealed bytes (store only)
}

func (s *storageExecutor) Run(_ context.Context, job contribute.AssignedJob) (contribute.Result, error) {
	var op storageOp
	if err := json.Unmarshal(job.Payload, &op); err != nil {
		return contribute.Result{JobID: job.ID}, fmt.Errorf("storage: bad payload: %w", err)
	}
	switch op.Op {
	case "store":
		return s.store(job.ID, op)
	case "audit":
		return s.audit(job.ID, op.ID)
	default:
		return contribute.Result{JobID: job.ID}, fmt.Errorf("storage: unknown op %q", op.Op)
	}
}

func (s *storageExecutor) store(jobID string, op storageOp) (contribute.Result, error) {
	blob, err := base64.StdEncoding.DecodeString(op.Data)
	if err != nil {
		return contribute.Result{JobID: jobID}, fmt.Errorf("storage: bad data: %w", err)
	}
	if len(blob) == 0 {
		return contribute.Result{JobID: jobID}, errors.New("storage: empty shard")
	}
	s.mu.Lock()
	s.shards[op.ID] = blob
	n := len(blob)
	s.mu.Unlock()
	return contribute.Result{JobID: jobID, OK: true, Detail: fmt.Sprintf("stored %d opaque bytes for %s", n, op.ID)}, nil
}

func (s *storageExecutor) audit(jobID, shardID string) (contribute.Result, error) {
	s.mu.Lock()
	blob, ok := s.shards[shardID]
	s.mu.Unlock()
	if !ok {
		return contribute.Result{JobID: jobID}, fmt.Errorf("storage: no shard %s", shardID)
	}
	// In production the challenge table is precomputed on the member's
	// device and only expected digests travel; here we build and check it
	// in one place to exercise the primitive end to end.
	verified, err := s.provePossession(blob)
	if err != nil {
		return contribute.Result{JobID: jobID}, err
	}
	if !verified {
		return contribute.Result{JobID: jobID, OK: false, Detail: "possession proof did not verify"}, nil
	}
	return contribute.Result{JobID: jobID, OK: true, Detail: fmt.Sprintf("possession proven for %s", shardID)}, nil
}

func (s *storageExecutor) provePossession(blob []byte) (bool, error) {
	table, err := storage.BuildChallengeTable(blob, s.audits, rand.Reader)
	if err != nil {
		return false, err
	}
	challenge, expected, err := table.Next()
	if err != nil {
		return false, err
	}
	response, err := storage.Respond(blob, challenge)
	if err != nil {
		return false, err
	}
	return storage.VerifyProof(expected, response), nil
}
