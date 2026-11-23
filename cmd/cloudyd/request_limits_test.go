package main

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestRequestLimitFlagsAreAvailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "go", "run", ".", "-help").CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v\n%s", err, output)
	}
	for _, flag := range []string{"-request-bytes", "-claim-request-bytes"} {
		if !bytes.Contains(output, []byte(flag)) {
			t.Errorf("help does not expose %s\n%s", flag, output)
		}
	}
}

func TestRequestLimitFlagsRejectInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{{"-request-bytes", "0"}, {"-claim-request-bytes", "-1"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		output, err := exec.CommandContext(ctx, "go", append([]string{"run", "."}, args...)...).CombinedOutput()
		cancel()
		if err == nil || !bytes.Contains(output, []byte("request byte limits must be positive")) {
			t.Errorf("invalid limits %v: err=%v output=%s", args, err, output)
		}
	}
}
