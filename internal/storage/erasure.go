package storage

import (
	"errors"
	"fmt"
)

// Coder turns a padded object into fixed-size shards and back. The seam
// exists so the redundancy scheme is swappable without touching sealing,
// quantization, placement, or audit — the countermeasures are agnostic to
// how shards are derived.
type Coder interface {
	// DataShards is how many shards carry payload.
	DataShards() int
	// TotalShards is how many shards exist including parity. Reconstruction
	// must succeed from any DataShards of them for a real erasure code.
	TotalShards() int
	// Encode splits data (whose length must be DataShards*shardSize) into
	// TotalShards shards of shardSize bytes each.
	Encode(data []byte, shardSize int) ([][]byte, error)
	// Reconstruct rebuilds the padded object from shards; a missing shard is
	// a nil entry at its index.
	Reconstruct(shards [][]byte) ([]byte, error)
}

var (
	// ErrShardMissing is returned by a coder that cannot tolerate the loss.
	ErrShardMissing = errors.New("storage: shard missing")
	errEncodeLength = errors.New("storage: encode input is not dataShards*shardSize")
)

// StandInSplitter is a LABELED STAND-IN for a real erasure code: it splits
// into K data shards with NO parity, so it tolerates ZERO shard loss. It
// exists so the privacy pipeline (quantize → seal → place → audit) is real
// and tested while Reed-Solomon k-of-n remains the named follow-up — the
// same discipline as the record layer's single-witness StandIn. Do not ship
// durability claims on top of this coder.
type StandInSplitter struct {
	K int // number of data shards; must be >= 1
}

func (s StandInSplitter) DataShards() int  { return s.K }
func (s StandInSplitter) TotalShards() int { return s.K }

func (s StandInSplitter) Encode(data []byte, shardSize int) ([][]byte, error) {
	if s.K < 1 {
		return nil, fmt.Errorf("storage: StandInSplitter.K must be >= 1, got %d", s.K)
	}
	if len(data) != s.K*shardSize {
		return nil, fmt.Errorf("%w: len %d, want %d*%d", errEncodeLength, len(data), s.K, shardSize)
	}
	out := make([][]byte, s.K)
	for i := 0; i < s.K; i++ {
		shard := make([]byte, shardSize)
		copy(shard, data[i*shardSize:(i+1)*shardSize])
		out[i] = shard
	}
	return out, nil
}

func (s StandInSplitter) Reconstruct(shards [][]byte) ([]byte, error) {
	if len(shards) != s.K {
		return nil, fmt.Errorf("storage: reconstruct got %d shards, want %d", len(shards), s.K)
	}
	var total int
	for i, sh := range shards {
		if sh == nil {
			return nil, fmt.Errorf("%w: index %d (StandInSplitter has no parity)", ErrShardMissing, i)
		}
		total += len(sh)
	}
	out := make([]byte, 0, total)
	for _, sh := range shards {
		out = append(out, sh...)
	}
	return out, nil
}
