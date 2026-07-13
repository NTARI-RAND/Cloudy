package opcred

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// mustKeyset generates a keyset or fails the test.
func mustKeyset(t *testing.T) *Keyset {
	t.Helper()
	ks, err := GenerateKeyset()
	if err != nil {
		t.Fatalf("GenerateKeyset: %v", err)
	}
	return ks
}

func TestKeysetSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keyset")
	ks := mustKeyset(t)
	if err := ks.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadKeyset(dir)
	if err != nil {
		t.Fatalf("LoadKeyset: %v", err)
	}

	gotPubs := loaded.PublicKeys()
	wantPubs := ks.PublicKeys()
	for i := range wantPubs {
		if !bytes.Equal(gotPubs[i], wantPubs[i]) {
			t.Errorf("public key %d differs after round-trip", i)
		}
	}
	if loaded.Hash() != ks.Hash() {
		t.Error("keyset hash differs after round-trip")
	}

	// The loaded private keys must actually sign: a full 2-of-7 transmission
	// signed by the loaded keyset verifies against the original public keys.
	tx := operator.OperatorTransmission{
		OperatorID: "op-roundtrip",
		TsUnixNano: 42,
		Nonce:      bytes.Repeat([]byte{7}, operator.MinNonceLen),
		Seq:        1,
		Algo:       operator.AlgoEd25519,
	}
	tx.Sign(loaded.priv[2], loaded.priv[5], 2, 5)
	if err := tx.Verify(ks.KeyMap()); err != nil {
		t.Errorf("transmission signed by loaded keys does not verify: %v", err)
	}
}

func TestSaveRefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keyset")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A pre-existing key-3.seed must abort the whole save before ANY write.
	collider := filepath.Join(dir, "key-3.seed")
	if err := os.WriteFile(collider, []byte("pre-existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	ks := mustKeyset(t)
	err := ks.Save(dir)
	if !errors.Is(err, ErrKeysetFileExists) {
		t.Fatalf("Save = %v, want ErrKeysetFileExists", err)
	}

	// No other file may have been created (no partial overwrite).
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 {
		t.Errorf("dir has %d entries after refused save, want only the collider", len(entries))
	}
	// The collider itself is untouched.
	got, readFileErr := os.ReadFile(collider)
	if readFileErr != nil {
		t.Fatal(readFileErr)
	}
	if string(got) != "pre-existing" {
		t.Error("collider file was clobbered")
	}
}

func TestLoadKeysetFailures(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, dir string)
		wantErr error // nil means "any error"
	}{
		{
			name: "missing file",
			mutate: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "key-2.seed")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "truncated seed",
			mutate: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "key-4.seed"), make([]byte, 16), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrBadSeed,
		},
		{
			name: "duplicate seed across two indices",
			mutate: func(t *testing.T, dir string) {
				seed, err := os.ReadFile(filepath.Join(dir, "key-0.seed"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "key-1.seed"), seed, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrDuplicateKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "keyset")
			if err := mustKeyset(t).Save(dir); err != nil {
				t.Fatalf("Save: %v", err)
			}
			tc.mutate(t, dir)
			_, err := LoadKeyset(dir)
			if err == nil {
				t.Fatal("LoadKeyset succeeded, want error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("LoadKeyset = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestKeysetCustodyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not enforced on Windows")
	}
	dir := filepath.Join(t.TempDir(), "keyset")
	if err := mustKeyset(t).Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("keyset dir perm = %o, want 700", perm)
	}
	for i := 0; i < operator.KeyIndexCount; i++ {
		fi, err := os.Stat(filepath.Join(dir, seedFileName(i)))
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("seed file %d perm = %o, want 600", i, perm)
		}
	}
}
