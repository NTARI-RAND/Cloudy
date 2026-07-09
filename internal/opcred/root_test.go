package opcred

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func mustFileRoot(t *testing.T) *FileRootSigner {
	t.Helper()
	rs, err := GenerateFileRoot(filepath.Join(t.TempDir(), "root.seed"))
	if err != nil {
		t.Fatalf("GenerateFileRoot: %v", err)
	}
	return rs
}

func TestFileRootRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.seed")
	rs, err := GenerateFileRoot(path)
	if err != nil {
		t.Fatalf("GenerateFileRoot: %v", err)
	}
	if !rs.StandIn() {
		t.Error("FileRootSigner.StandIn() = false, want true (software stand-in must self-label)")
	}

	loaded, err := LoadFileRoot(path)
	if err != nil {
		t.Fatalf("LoadFileRoot: %v", err)
	}
	if !bytes.Equal(rs.PublicKey(), loaded.PublicKey()) {
		t.Error("public key differs after round-trip")
	}

	msg := []byte("root round-trip probe")
	sig, err := loaded.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(rs.PublicKey(), msg, sig) {
		t.Error("loaded root signature does not verify against generated public key")
	}
}

func TestGenerateFileRootRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.seed")
	if _, err := GenerateFileRoot(path); err != nil {
		t.Fatalf("first GenerateFileRoot: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := GenerateFileRoot(path); !errors.Is(err, ErrRootFileExists) {
		t.Fatalf("second GenerateFileRoot = %v, want ErrRootFileExists", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("existing root seed was clobbered")
	}
}

func TestFileRootPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "root.seed")
	if _, err := GenerateFileRoot(path); err != nil {
		t.Fatalf("GenerateFileRoot: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("root seed perm = %o, want 600", perm)
	}
}

func TestDelegationWindow(t *testing.T) {
	ks := mustKeyset(t)
	rs := mustFileRoot(t)

	notBefore := time.Unix(0, 1_000_000_000_000)
	notAfter := notBefore.Add(24 * time.Hour)
	d, err := IssueDelegation(rs, ks, notBefore, notAfter)
	if err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}

	tests := []struct {
		name    string
		at      time.Time
		wantErr error
	}{
		{"before window", notBefore.Add(-time.Nanosecond), ErrDelegationNotYetValid},
		{"at NotBefore (inclusive)", notBefore, nil},
		{"inside window", notBefore.Add(12 * time.Hour), nil},
		{"at NotAfter (inclusive)", notAfter, nil},
		{"after window", notAfter.Add(time.Nanosecond), ErrDelegationExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyDelegation(d, rs.PublicKey(), ks.Hash(), tc.at)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("VerifyDelegation = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDelegationRejectsMismatchAndTamper(t *testing.T) {
	ks := mustKeyset(t)
	rs := mustFileRoot(t)
	notBefore := time.Unix(0, 2_000_000_000_000)
	notAfter := notBefore.Add(time.Hour)
	inside := notBefore.Add(time.Minute)

	tests := []struct {
		name    string
		setup   func(t *testing.T) (Delegation, ed25519.PublicKey, [32]byte)
		wantErr error
	}{
		{
			name: "keyset mismatch",
			setup: func(t *testing.T) (Delegation, ed25519.PublicKey, [32]byte) {
				d, err := IssueDelegation(rs, ks, notBefore, notAfter)
				if err != nil {
					t.Fatal(err)
				}
				other := mustKeyset(t)
				return d, rs.PublicKey(), other.Hash()
			},
			wantErr: ErrDelegationKeysetMismatch,
		},
		{
			name: "tampered signature",
			setup: func(t *testing.T) (Delegation, ed25519.PublicKey, [32]byte) {
				d, err := IssueDelegation(rs, ks, notBefore, notAfter)
				if err != nil {
					t.Fatal(err)
				}
				d.Sig[0] ^= 0xff
				return d, rs.PublicKey(), ks.Hash()
			},
			wantErr: ErrDelegationBadSignature,
		},
		{
			name: "tampered window bound",
			setup: func(t *testing.T) (Delegation, ed25519.PublicKey, [32]byte) {
				d, err := IssueDelegation(rs, ks, notBefore, notAfter)
				if err != nil {
					t.Fatal(err)
				}
				d.NotAfter = notAfter.Add(365 * 24 * time.Hour).UnixNano()
				return d, rs.PublicKey(), ks.Hash()
			},
			wantErr: ErrDelegationBadSignature,
		},
		{
			name: "swapped-in carried root key cannot self-authorize",
			setup: func(t *testing.T) (Delegation, ed25519.PublicKey, [32]byte) {
				// A rogue root issues a delegation and carries its own public
				// key in RootPub; verification pins the REAL root key, so the
				// rogue delegation must fail as a bad signature.
				rogue := mustFileRoot(t)
				d, err := IssueDelegation(rogue, ks, notBefore, notAfter)
				if err != nil {
					t.Fatal(err)
				}
				return d, rs.PublicKey(), ks.Hash()
			},
			wantErr: ErrDelegationBadSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, pin, hash := tc.setup(t)
			if err := VerifyDelegation(d, pin, hash, inside); !errors.Is(err, tc.wantErr) {
				t.Errorf("VerifyDelegation = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestIssueDelegationRejectsBadWindows(t *testing.T) {
	ks := mustKeyset(t)
	rs := mustFileRoot(t)
	base := time.Unix(0, 3_000_000_000_000)

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantErr   error
	}{
		{"inverted window", base.Add(time.Hour), base, ErrDelegationWindow},
		{"empty window", base, base, ErrDelegationWindow},
		{"TTL over max", base, base.Add(MaxDelegationTTL + time.Nanosecond), ErrDelegationTTL},
		{"TTL at max is allowed", base, base.Add(MaxDelegationTTL), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := IssueDelegation(rs, ks, tc.notBefore, tc.notAfter)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("IssueDelegation = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
