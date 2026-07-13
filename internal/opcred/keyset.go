package opcred

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// keysetHashDomain tags the canonical bytes the keyset hash is computed over,
// so the hash can never be confused with any other digest in the system.
const keysetHashDomain = "cloudy/opcred/keyset/v0"

// Errors returned by keyset custody. They are distinguishable so a caller can
// map each to the right operator-facing message.
var (
	// ErrKeysetFileExists is returned by Save when ANY of the seven seed files
	// already exists at the destination. Save never overwrites and never
	// partially writes: the collision is detected before any file is created.
	ErrKeysetFileExists = errors.New("opcred: a keyset seed file already exists; refusing to overwrite")
	// ErrDuplicateKey is returned by LoadKeyset when two indices resolve to the
	// same key (e.g. a copy-pasted seed file). It mirrors the protocol's
	// ErrDuplicateSigningKey so the 2-of-7 degradation is caught at load time
	// on the operator's own machine, not at coordinator verify time.
	ErrDuplicateKey = errors.New("opcred: two keyset indices hold the same key")
	// ErrBadSeed is returned by LoadKeyset for a seed file of the wrong length
	// or a key that fails its sign-then-verify probe.
	ErrBadSeed = errors.New("opcred: seed file is malformed")
)

// Keyset is the operator's seven Ed25519 keypairs, indexed
// 0..operator.KeyIndexCount-1. Private keys are unexported and never leave
// this package except as signatures.
type Keyset struct {
	priv [operator.KeyIndexCount]ed25519.PrivateKey
	pub  [operator.KeyIndexCount]ed25519.PublicKey
}

// GenerateKeyset creates seven fresh keypairs from crypto/rand.
func GenerateKeyset() (*Keyset, error) {
	ks := &Keyset{}
	for i := 0; i < operator.KeyIndexCount; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("opcred: generate key %d: %w", i, err)
		}
		ks.priv[i] = priv
		ks.pub[i] = pub
	}
	return ks, nil
}

// seedFileName returns the on-disk file name for the key at index i.
func seedFileName(i int) string {
	return fmt.Sprintf("key-%d.seed", i)
}

// Save writes the keyset to dir as seven files key-0.seed .. key-6.seed, each
// holding the 32-byte Ed25519 SEED (not the 64-byte expanded private key).
// Storing the seed and re-deriving via ed25519.NewKeyFromSeed structurally
// eliminates the mismatched-halves failure mode of storing a full private key
// whose public half could drift from its private half.
//
// The directory is created 0700 and each file 0600 with O_EXCL. If ANY of the
// seven paths already exists, Save returns ErrKeysetFileExists (naming the
// colliding file) BEFORE writing anything, so a collision never leaves a
// partially overwritten keyset.
func (ks *Keyset) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("opcred: create keyset dir: %w", err)
	}
	// Pre-check all seven paths so a collision aborts before any write.
	for i := 0; i < operator.KeyIndexCount; i++ {
		path := filepath.Join(dir, seedFileName(i))
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%w: %s", ErrKeysetFileExists, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("opcred: stat %s: %w", path, err)
		}
	}
	for i := 0; i < operator.KeyIndexCount; i++ {
		path := filepath.Join(dir, seedFileName(i))
		if err := writeSeedFile(path, ks.priv[i].Seed()); err != nil {
			return err
		}
	}
	return nil
}

// writeSeedFile writes a 32-byte seed at path, 0600, refusing to overwrite.
func writeSeedFile(path string, seed []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKeysetFileExists, path)
		}
		return fmt.Errorf("opcred: create %s: %w", path, err)
	}
	if _, err := f.Write(seed); err != nil {
		f.Close()
		return fmt.Errorf("opcred: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("opcred: close %s: %w", path, err)
	}
	return nil
}

// LoadKeyset reads a keyset saved by Save. It requires all seven seed files,
// each exactly ed25519.SeedSize bytes; runs a sign-then-verify probe on every
// derived key; and rejects a keyset whose public keys are not pairwise
// distinct (ErrDuplicateKey), mirroring the coordinator-side
// ErrDuplicateSigningKey check so the failure surfaces locally.
func LoadKeyset(dir string) (*Keyset, error) {
	ks := &Keyset{}
	for i := 0; i < operator.KeyIndexCount; i++ {
		path := filepath.Join(dir, seedFileName(i))
		seed, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("opcred: read seed %d: %w", i, err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%w: %s is %d bytes, want %d", ErrBadSeed, path, len(seed), ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: %s public half is not Ed25519", ErrBadSeed, path)
		}
		if err := probeKey(priv, pub); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrBadSeed, path, err)
		}
		ks.priv[i] = priv
		ks.pub[i] = pub
	}
	for i := 0; i < operator.KeyIndexCount; i++ {
		for j := i + 1; j < operator.KeyIndexCount; j++ {
			if bytes.Equal(ks.pub[i], ks.pub[j]) {
				return nil, fmt.Errorf("%w: indices %d and %d", ErrDuplicateKey, i, j)
			}
		}
	}
	return ks, nil
}

// probeKey signs a fixed message and verifies it, proving the private and
// public halves belong together before the key is ever used for real.
func probeKey(priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	msg := []byte("opcred keyset load probe")
	if !ed25519.Verify(pub, msg, ed25519.Sign(priv, msg)) {
		return errors.New("sign-then-verify probe failed")
	}
	return nil
}

// PublicKeys returns the seven raw 32-byte public keys in index order — the
// exact shape the coordinator's key-registration endpoint wants after base64.
func (ks *Keyset) PublicKeys() [][]byte {
	out := make([][]byte, operator.KeyIndexCount)
	for i := 0; i < operator.KeyIndexCount; i++ {
		out[i] = append([]byte(nil), ks.pub[i]...)
	}
	return out
}

// KeyMap returns the keyset as the registered-key map the protocol's Verify
// paths take, for local verification and tests.
func (ks *Keyset) KeyMap() map[int]operator.KeyRecord {
	m := make(map[int]operator.KeyRecord, operator.KeyIndexCount)
	for i := 0; i < operator.KeyIndexCount; i++ {
		m[i] = operator.KeyRecord{
			PublicKey: append([]byte(nil), ks.pub[i]...),
			Algo:      operator.AlgoEd25519,
		}
	}
	return m
}

// Hash returns the online keyset hash: sha256 over domain-tagged canonical
// bytes of the seven public keys in index order. This is the value a root
// delegation signs over, binding the delegation to this exact keyset.
func (ks *Keyset) Hash() [32]byte {
	b := canon.New(keysetHashDomain)
	for i := 0; i < operator.KeyIndexCount; i++ {
		b.Bytes(ks.pub[i])
	}
	return sha256.Sum256(b.Sum())
}
