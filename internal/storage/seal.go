package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ObjectKey is the random symmetric key for one object, generated on the
// member's device and held only in the member's manifest (Locker). It never
// travels to a host, to cloudyd's commons, or onto the wire — the host-side
// guarantee of §5a layer 1 is that this key's absence makes a shard noise.
type ObjectKey [32]byte

// ObjectID names an object inside the member's own manifest. It is chosen
// randomly, NOT derived from content — content-derived IDs would leak
// equality of plaintexts (convergent-encryption confirmation), which is the
// exact class of inference this package exists to prevent.
type ObjectID [32]byte

// Shard is one sealed, content-addressed fragment. Ref is what a host and
// the placement layer see; it is the SHA-256 of Sealed and carries no member,
// object, or position meaning to anyone without the manifest.
type Shard struct {
	Ref    [32]byte
	Sealed []byte
}

var (
	// ErrOpenShard means authentication failed: the shard was tampered with,
	// belongs to a different object, or sits at a different index than the
	// manifest claims.
	ErrOpenShard = errors.New("storage: shard failed authenticated open")
)

// NewObjectKey draws a fresh random object key.
func NewObjectKey(rand io.Reader) (ObjectKey, error) {
	var k ObjectKey
	if _, err := io.ReadFull(rand, k[:]); err != nil {
		return ObjectKey{}, fmt.Errorf("storage: reading object key: %w", err)
	}
	return k, nil
}

// NewObjectID draws a fresh random object ID.
func NewObjectID(rand io.Reader) (ObjectID, error) {
	var id ObjectID
	if _, err := io.ReadFull(rand, id[:]); err != nil {
		return ObjectID{}, fmt.Errorf("storage: reading object id: %w", err)
	}
	return id, nil
}

// gcmFor builds the AEAD for an object key.
func gcmFor(key ObjectKey) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// shardNonce is a counter nonce: safe because every object has its own
// random key, so (key, nonce) pairs never repeat across shards or objects.
func shardNonce(index int) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], uint64(index))
	return n
}

// shardAAD binds a shard to its object and position so a host (or a
// compromised relay) cannot swap shards between objects or reorder them
// without detection at open time.
func shardAAD(objectID ObjectID, index int) []byte {
	aad := make([]byte, len(objectID)+8)
	copy(aad, objectID[:])
	binary.BigEndian.PutUint64(aad[len(objectID):], uint64(index))
	return aad
}

// sealShard encrypts one padded shard payload. All payloads in a size class
// have identical length, and AES-GCM adds a fixed 16-byte tag, so all sealed
// shards in a class are the same wire size — quantization survives sealing.
func sealShard(key ObjectKey, objectID ObjectID, index int, payload []byte) (Shard, error) {
	aead, err := gcmFor(key)
	if err != nil {
		return Shard{}, fmt.Errorf("storage: sealing shard %d: %w", index, err)
	}
	sealed := aead.Seal(nil, shardNonce(index), payload, shardAAD(objectID, index))
	return Shard{Ref: sha256.Sum256(sealed), Sealed: sealed}, nil
}

// openShard authenticates and decrypts one sealed shard at a claimed index.
func openShard(key ObjectKey, objectID ObjectID, index int, sealed []byte) ([]byte, error) {
	aead, err := gcmFor(key)
	if err != nil {
		return nil, fmt.Errorf("storage: opening shard %d: %w", index, err)
	}
	payload, err := aead.Open(nil, shardNonce(index), sealed, shardAAD(objectID, index))
	if err != nil {
		return nil, fmt.Errorf("%w (index %d)", ErrOpenShard, index)
	}
	return payload, nil
}
