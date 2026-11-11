package main

import (
	"os/exec"
	"strings"
	"testing"
)

// macOS ACL read grants are not reflected in mode bits.
func TestWitnessSeedFileRejectsACL(t *testing.T) {
	path := writeSeed(t, testSeed, 0600)
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read", path).CombinedOutput(); err != nil {
		t.Fatalf("set fixture ACL: %v %s", err, out)
	}
	out := startup(t, seedDaemon(t), "-seed-file", path)
	if strings.Contains(out, "witness key ") || !strings.Contains(out, "ACL") {
		t.Fatalf("readable ACL accepted: %s", out)
	}
}
