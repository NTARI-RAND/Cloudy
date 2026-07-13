package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/opcred"
	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    func(t *testing.T, dir string) []string
		prepare func(t *testing.T, dir string)
		wantErr bool
		check   func(t *testing.T, dir, out string)
	}{
		{
			name: "happy path writes keyset and prints seven public keys",
			args: func(t *testing.T, dir string) []string {
				return []string{"-dir", dir}
			},
			check: func(t *testing.T, dir, out string) {
				ks, err := opcred.LoadKeyset(dir)
				if err != nil {
					t.Fatalf("LoadKeyset after run: %v", err)
				}
				// Output contains exactly the seven base64 public keys, in
				// index order, as "  <i>: <base64>" lines.
				var printed []string
				for _, line := range strings.Split(out, "\n") {
					line = strings.TrimSpace(line)
					want := prefixForIndex(len(printed))
					if strings.HasPrefix(line, want) {
						printed = append(printed, strings.TrimPrefix(line, want))
					}
				}
				if len(printed) != operator.KeyIndexCount {
					t.Fatalf("printed %d public keys, want %d", len(printed), operator.KeyIndexCount)
				}
				for i, b64 := range printed {
					raw, err := base64.StdEncoding.DecodeString(b64)
					if err != nil {
						t.Fatalf("key %d is not valid base64: %v", i, err)
					}
					if !bytes.Equal(raw, ks.PublicKeys()[i]) {
						t.Errorf("printed key %d does not match the saved keyset", i)
					}
				}
				// Never any private material: no seed appears in the output.
				for i := 0; i < operator.KeyIndexCount; i++ {
					seed, err := os.ReadFile(filepath.Join(dir, seedName(i)))
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(out, base64.StdEncoding.EncodeToString(seed)) {
						t.Fatalf("output contains the base64 of seed %d", i)
					}
				}
			},
		},
		{
			name: "second run on the same dir refuses to overwrite",
			args: func(t *testing.T, dir string) []string {
				return []string{"-dir", dir}
			},
			prepare: func(t *testing.T, dir string) {
				if err := run([]string{"-dir", dir}, &bytes.Buffer{}); err != nil {
					t.Fatalf("first run: %v", err)
				}
			},
			wantErr: true,
		},
		{
			name: "missing -dir is an error",
			args: func(t *testing.T, dir string) []string {
				return nil
			},
			wantErr: true,
		},
		{
			name: "-root also bootstraps the file root",
			args: func(t *testing.T, dir string) []string {
				return []string{"-dir", dir, "-root", filepath.Join(dir, "root", "root.seed")}
			},
			check: func(t *testing.T, dir, out string) {
				rs, err := opcred.LoadFileRoot(filepath.Join(dir, "root", "root.seed"))
				if err != nil {
					t.Fatalf("LoadFileRoot after run: %v", err)
				}
				want := base64.StdEncoding.EncodeToString(rs.PublicKey())
				if !strings.Contains(out, want) {
					t.Error("output does not contain the root public key")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "keyset")
			if tc.prepare != nil {
				tc.prepare(t, dir)
			}
			var buf bytes.Buffer
			err := run(tc.args(t, dir), &buf)
			if tc.wantErr {
				if err == nil {
					t.Fatal("run succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if tc.check != nil {
				tc.check(t, dir, buf.String())
			}
		})
	}
}

// prefixForIndex is the printed line prefix for public key i.
func prefixForIndex(i int) string {
	return string(rune('0'+i)) + ": "
}

// seedName mirrors the keyset's on-disk file naming.
func seedName(i int) string {
	return "key-" + string(rune('0'+i)) + ".seed"
}
