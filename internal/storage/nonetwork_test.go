package storage

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoNetworkImport is the real tripwire behind relay.go's promise: the
// member-side storage package must never pull in a networking package, so it
// is structurally incapable of dialing a host directly (all shard traffic must
// cross the Relay seam, which cloudyd implements). It walks the full
// transitive import graph via `go list -deps` and fails if any dependency is
// a net package. A future edit that adds `net`/`net/http` to reach a host
// turns this test red at build-check time.
//
// Replaces a comment that previously claimed test/composition made this
// assertion; it did not. This does.
func TestNoNetworkImport(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go toolchain unavailable (%v); import-graph tripwire not run", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "net" || strings.HasPrefix(dep, "net/") {
			t.Fatalf("storage transitively imports networking package %q — "+
				"member-side code must reach hosts only through the Relay seam, never dial directly", dep)
		}
	}
}
