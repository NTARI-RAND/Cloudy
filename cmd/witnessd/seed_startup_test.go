package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const seedFileFlag = "-seed-file"
const keyLogPrefix = "witness key "
const daemonErrorPrefix = "witnessd:"

const testSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
const testPublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

func seedDaemon(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "witnessd")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	return binary
}

func startup(t *testing.T, binary string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	args = append([]string{"-relay", "http://127.0.0.1:1", "-intake", "127.0.0.1:0", "-interval", "1h"}, args...)
	out, _ := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	return string(out)
}

func writeSeed(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "witness.seed")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// Catches ignored file input, unstable identity, and secret disclosure at startup.
func TestWitnessSeedFileIdentity(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("protected files supported on Linux and macOS")
	}
	binary := seedDaemon(t)
	path := writeSeed(t, testSeed+"\n", 0600)
	for i := 0; i < 2; i++ {
		out := startup(t, binary, seedFileFlag, path)
		if !strings.Contains(out, keyLogPrefix+testPublicKey) {
			t.Fatalf("persistent identity missing: %s", out)
		}
		if strings.Contains(out, testSeed) || strings.Contains(out, "EPHEMERAL") {
			t.Fatal("secret leaked or persistent input ignored")
		}
	}
}

// Catches falling back to an ephemeral key after an invalid persistent input.
func TestWitnessSeedFileRejectsUnsafeInput(t *testing.T) {
	binary := seedDaemon(t)
	cases := []struct {
		name, content string
		mode          os.FileMode
	}{
		{"bad hex", strings.Repeat("z", 64), 0600},
		{"short", "ab", 0600},
		{"oversized", strings.Repeat("a", 4096), 0600},
		{"group readable", testSeed, 0640},
		{"world readable", testSeed, 0604},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := startup(t, binary, seedFileFlag, writeSeed(t, tc.content, tc.mode))
			if !strings.Contains(out, daemonErrorPrefix) || strings.Contains(out, keyLogPrefix) || strings.Contains(out, "EPHEMERAL") {
				t.Fatalf("expected startup rejection: %s", out)
			}
			if strings.Contains(out, tc.content) {
				t.Fatal("seed content leaked")
			}
		})
	}
	for name, path := range map[string]string{"missing": filepath.Join(t.TempDir(), "absent"), "directory": t.TempDir()} {
		t.Run(name, func(t *testing.T) {
			out := startup(t, binary, seedFileFlag, path)
			if !strings.Contains(out, daemonErrorPrefix) || strings.Contains(out, keyLogPrefix) {
				t.Fatalf("expected rejection: %s", out)
			}
		})
	}
}

func TestWitnessSeedFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Unix symlink policy")
	}
	binary := seedDaemon(t)
	path := writeSeed(t, testSeed, 0600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	out := startup(t, binary, seedFileFlag, link)
	if !strings.Contains(out, daemonErrorPrefix) || strings.Contains(out, keyLogPrefix) {
		t.Fatalf("expected symlink rejection: %s", out)
	}
}

func TestWitnessSeedCompatibility(t *testing.T) {
	binary := seedDaemon(t)
	t.Run("legacy", func(t *testing.T) {
		out := startup(t, binary, "-seed", testSeed)
		if !strings.Contains(out, keyLogPrefix+testPublicKey) || !strings.Contains(out, "deprecated") || strings.Contains(out, testSeed) {
			t.Fatalf("legacy migration behavior incorrect: %s", out)
		}
	})
	t.Run("demo", func(t *testing.T) {
		out := startup(t, binary)
		if !strings.Contains(out, "EPHEMERAL") || !strings.Contains(out, keyLogPrefix) {
			t.Fatalf("demo key missing: %s", out)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		out := startup(t, binary, "-seed", testSeed, seedFileFlag, writeSeed(t, testSeed, 0600))
		if !strings.Contains(out, "mutually exclusive") || strings.Contains(out, testSeed) || strings.Contains(out, keyLogPrefix) {
			t.Fatalf("conflicting options accepted: %s", out)
		}
	})
}
