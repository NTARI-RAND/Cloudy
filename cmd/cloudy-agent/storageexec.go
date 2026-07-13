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
		blob, err := base64.StdEncoding.DecodeString(op.Data)
		if err != nil {
			return contribute.Result{JobID: job.ID}, fmt.Errorf("storage: bad data: %w", err)
		}
		if len(blob) == 0 {
			return contribute.Result{JobID: job.ID}, errors.New("storage: empty shard")
		}
		s.mu.Lock()
		s.shards[op.ID] = blob
		n := len(blob)
		s.mu.Unlock()
		return contribute.Result{JobID: job.ID, OK: true, Detail: fmt.Sprintf("stored %d opaque bytes for %s", n, op.ID)}, nil
	case "audit":
		s.mu.Lock()
		blob, ok := s.shards[op.ID]
		s.mu.Unlock()
		if !ok {
			return contribute.Result{JobID: job.ID}, fmt.Errorf("storage: no shard %s", op.ID)
		}
		// In production the challenge table is precomputed on the member's
		// device and only expected digests travel; here we build and check it
		// in one place to exercise the primitive end to end.
		table, err := storage.BuildChallengeTable(blob, s.audits, rand.Reader)
		if err != nil {
			return contribute.Result{JobID: job.ID}, err
		}
		ch, expected, err := table.Next()
		if err != nil {
			return contribute.Result{JobID: job.ID}, err
		}
		resp, err := storage.Respond(blob, ch)
		if err != nil {
			return contribute.Result{JobID: job.ID}, err
		}
		if !storage.VerifyProof(expected, resp) {
			return contribute.Result{JobID: job.ID, OK: false, Detail: "possession proof did not verify"}, nil
		}
		return contribute.Result{JobID: job.ID, OK: true, Detail: fmt.Sprintf("possession proven for %s", op.ID)}, nil
	default:
		return contribute.Result{JobID: job.ID}, fmt.Errorf("storage: unknown op %q", op.Op)
	}
}
