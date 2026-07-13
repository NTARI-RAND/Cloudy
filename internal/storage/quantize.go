package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Class is a quantized shard-payload size. Every shard payload in a class is
// padded to exactly the class size before sealing, so all sealed shards of a
// class are byte-for-byte the same length on the wire and on disk — a host
// cannot fingerprint an object by shard size (countermeasure 1). The protocol
// side speaks ONLY in classes, never true sizes.
type Class int64

const (
	ClassSmall  Class = 1 << 20  // 1 MiB
	ClassMedium Class = 16 << 20 // 16 MiB
	ClassLarge  Class = 64 << 20 // 64 MiB
)

// classes in ascending order, for selection.
var classes = []Class{ClassSmall, ClassMedium, ClassLarge}

// frameOverhead is the length prefix framed into the padded payload so unpad
// can recover the true byte count.
const frameOverhead = 8

var (
	// ErrObjectTooLarge means the framed object exceeds k shards of the
	// largest class. Callers split such objects above this layer; silently
	// spanning classes would recreate a size fingerprint.
	ErrObjectTooLarge = errors.New("storage: object exceeds largest size class")
	// ErrCorruptFrame means unpad found an impossible length prefix.
	ErrCorruptFrame = errors.New("storage: corrupt length frame")
)

// classFor returns the smallest class such that a framed payload of n bytes
// fits in dataShards shards of that class.
func classFor(n, dataShards int) (Class, error) {
	framed := int64(n) + frameOverhead
	for _, c := range classes {
		if framed <= int64(c)*int64(dataShards) {
			return c, nil
		}
	}
	return 0, fmt.Errorf("%w: %d bytes over %d shards", ErrObjectTooLarge, n, dataShards)
}

// pad frames plain with its length and pads the result to total bytes with
// random padding, so plaintexts of different sizes become indistinguishable
// once sealed. rand MUST be cryptographically strong in production; tests
// inject a deterministic reader.
func pad(plain []byte, total int64, rand io.Reader) ([]byte, error) {
	framed := int64(len(plain)) + frameOverhead
	if framed > total {
		return nil, fmt.Errorf("%w: %d framed bytes into %d", ErrObjectTooLarge, framed, total)
	}
	out := make([]byte, total)
	binary.BigEndian.PutUint64(out[:frameOverhead], uint64(len(plain)))
	copy(out[frameOverhead:], plain)
	if _, err := io.ReadFull(rand, out[framed:]); err != nil {
		return nil, fmt.Errorf("storage: reading padding: %w", err)
	}
	return out, nil
}

// unpad recovers the original payload from a padded frame.
func unpad(padded []byte) ([]byte, error) {
	if len(padded) < frameOverhead {
		return nil, ErrCorruptFrame
	}
	n := binary.BigEndian.Uint64(padded[:frameOverhead])
	if n > uint64(len(padded)-frameOverhead) {
		return nil, ErrCorruptFrame
	}
	out := make([]byte, n)
	copy(out, padded[frameOverhead:frameOverhead+int(n)])
	return out, nil
}
