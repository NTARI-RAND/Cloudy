package opcred

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrRootFileExists is returned by GenerateFileRoot when the seed file already
// exists. A root seed is never overwritten.
var ErrRootFileExists = errors.New("opcred: root seed file already exists; refusing to overwrite")

// FileRootSigner is the file-backed RootSigner: a 32-byte Ed25519 seed on
// local disk. It is a software STAND-IN for a device-held root —
// StandIn() reports true — and exists so the delegation structure can be
// exercised end to end before a device implementation lands.
type FileRootSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// GenerateFileRoot creates a fresh root seed at path (0600, refusing to
// overwrite an existing file) and returns the signer over it.
func GenerateFileRoot(path string) (*FileRootSigner, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("opcred: generate root seed: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("opcred: create root seed dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrRootFileExists, path)
		}
		return nil, fmt.Errorf("opcred: create root seed file: %w", err)
	}
	if _, err := f.Write(seed); err != nil {
		f.Close()
		return nil, fmt.Errorf("opcred: write root seed: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("opcred: close root seed: %w", err)
	}
	return newFileRootSigner(seed)
}

// LoadFileRoot reads a root seed written by GenerateFileRoot: exact length
// check plus a sign-then-verify probe before the key is trusted.
func LoadFileRoot(path string) (*FileRootSigner, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opcred: read root seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s is %d bytes, want %d", ErrBadSeed, path, len(seed), ed25519.SeedSize)
	}
	return newFileRootSigner(seed)
}

// newFileRootSigner derives the keypair from a seed and probes it.
func newFileRootSigner(seed []byte) (*FileRootSigner, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: root public half is not Ed25519", ErrBadSeed)
	}
	if err := probeKey(priv, pub); err != nil {
		return nil, fmt.Errorf("%w: root seed: %v", ErrBadSeed, err)
	}
	return &FileRootSigner{priv: priv, pub: pub}, nil
}

// PublicKey returns the root public key.
func (s *FileRootSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.pub...)
}

// Sign returns the root signature over msg.
func (s *FileRootSigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// StandIn reports true: this root is software-held on local disk, standing in
// for a device. A deployment MUST surface this to its operator.
func (s *FileRootSigner) StandIn() bool { return true }
