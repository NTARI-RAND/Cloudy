package storage

import (
	"fmt"
	"io"
)

// SealedObject is the member-side result of preparing an object for the
// network: uniformly sized sealed shards plus the class they were quantized
// to. The caller records key, id, class, and shard order in the member's
// manifest (Locker); only Shards leave the device.
type SealedObject struct {
	ID     ObjectID
	Class  Class
	Shards []Shard
}

// SealObject runs the full §5a pipeline: frame+pad the plaintext to the
// smallest class that fits the coder's data shards (countermeasure 1:
// quantization), split with the coder, and seal each shard bound to its
// object and index. Every returned shard has an identical Sealed length.
func SealObject(key ObjectKey, id ObjectID, plain []byte, coder Coder, rand io.Reader) (SealedObject, error) {
	class, err := classFor(len(plain), coder.DataShards())
	if err != nil {
		return SealedObject{}, err
	}
	padded, err := pad(plain, int64(class)*int64(coder.DataShards()), rand)
	if err != nil {
		return SealedObject{}, err
	}
	raw, err := coder.Encode(padded, int(class))
	if err != nil {
		return SealedObject{}, fmt.Errorf("storage: encoding shards: %w", err)
	}
	shards := make([]Shard, len(raw))
	for i, payload := range raw {
		shards[i], err = sealShard(key, id, i, payload)
		if err != nil {
			return SealedObject{}, err
		}
	}
	return SealedObject{ID: id, Class: class, Shards: shards}, nil
}

// OpenObject reverses SealObject. sealed holds each shard's Sealed bytes at
// its original index; a fetched-but-missing shard is a nil entry, tolerated
// only as far as the coder's parity allows.
func OpenObject(key ObjectKey, id ObjectID, sealed [][]byte, coder Coder) ([]byte, error) {
	raw := make([][]byte, len(sealed))
	for i, s := range sealed {
		if s == nil {
			continue
		}
		payload, err := openShard(key, id, i, s)
		if err != nil {
			return nil, err
		}
		raw[i] = payload
	}
	padded, err := coder.Reconstruct(raw)
	if err != nil {
		return nil, fmt.Errorf("storage: reconstructing object: %w", err)
	}
	return unpad(padded)
}
