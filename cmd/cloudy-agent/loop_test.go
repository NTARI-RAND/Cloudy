package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/employment"
	"github.com/NTARI-RAND/sohocloud-protocol/fees"
	"github.com/NTARI-RAND/sohocloud-protocol/identity"
	"github.com/NTARI-RAND/sohocloud-protocol/listing"
	"github.com/NTARI-RAND/sohocloud-protocol/liveness"
	"github.com/NTARI-RAND/sohocloud-protocol/transport/httpjson"

	"github.com/NTARI-RAND/Cloudy/internal/contribute"
	"github.com/NTARI-RAND/Cloudy/internal/coord"
	"github.com/NTARI-RAND/Cloudy/internal/noderelay"
)

// fakeCoord is a coordinator that checks what a real one checks — every node
// message verifies against the node's key, and Seq strictly increases — and
// hands out assignments it signs with its own key.
type fakeCoord struct {
	t        *testing.T
	nodePub  ed25519.PublicKey
	coordKey ed25519.PrivateKey

	mu       sync.Mutex
	listings []listing.CapabilityListing
	beats    int
	listSeq  uint64
	beatSeq  uint64
	queue    []employment.Assignment
	reports  map[string]employment.JobReport
	declines map[string]employment.Decline
}

var errBad = errors.New("rejected")

func (c *fakeCoord) SubmitListing(_ context.Context, l listing.CapabilityListing) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !l.Verify(c.nodePub) || l.Seq <= c.listSeq {
		c.t.Errorf("listing rejected: verify=%v seq=%d last=%d", l.Verify(c.nodePub), l.Seq, c.listSeq)
		return errBad
	}
	c.listSeq = l.Seq
	c.listings = append(c.listings, l)
	return nil
}

func (c *fakeCoord) Heartbeat(_ context.Context, h liveness.Heartbeat) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !h.Verify(c.nodePub) || h.Seq <= c.beatSeq {
		c.t.Errorf("heartbeat rejected: verify=%v seq=%d last=%d", h.Verify(c.nodePub), h.Seq, c.beatSeq)
		return errBad
	}
	c.beatSeq = h.Seq
	c.beats++
	return nil
}

func (c *fakeCoord) PollJobs(_ context.Context, id identity.NodeID) ([]employment.Assignment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Worst case: the coordinator keeps offering every assignment, settled or
	// not. The node must still settle each one exactly once.
	return append([]employment.Assignment(nil), c.queue...), nil
}

func (c *fakeCoord) Decline(_ context.Context, d employment.Decline) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !d.Verify(c.nodePub) {
		c.t.Error("decline does not verify")
		return errBad
	}
	if _, dup := c.declines[d.JobID]; dup {
		c.t.Errorf("job %s declined twice", d.JobID)
	}
	c.declines[d.JobID] = d
	return nil
}

func (c *fakeCoord) ReportJob(_ context.Context, r employment.JobReport) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !r.Verify(c.nodePub) {
		c.t.Error("report does not verify")
		return errBad
	}
	if _, dup := c.reports[r.JobID]; dup {
		c.t.Errorf("job %s reported twice", r.JobID)
	}
	c.reports[r.JobID] = r
	return nil
}

func (c *fakeCoord) Fees(context.Context) (fees.FeeDeclaration, error) {
	return fees.FeeDeclaration{}, nil
}

// assign queues a coordinator-signed assignment.
func (c *fakeCoord) assign(node identity.NodeID, id, workload string, args ...string) {
	a := employment.Assignment{
		JobID: id, NodeID: node, OfferedAt: time.Now().UTC(),
		Spec: employment.JobSpec{Workload: workload, Args: args},
	}
	a.Sign(c.coordKey)
	c.mu.Lock()
	c.queue = append(c.queue, a)
	c.mu.Unlock()
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// harness wires an Agent to a fakeCoord over the reference HTTP+JSON wire,
// through Cloudy's own coord client.
func harness(t *testing.T, placement contribute.Placement, ownerActive func() bool) (*Loop, *fakeCoord) {
	t.Helper()
	nodePub, nodeKey := genKey(t)
	_, coordKey := genKey(t)
	const node = identity.NodeID("cloudy-node-test")

	reg, err := contribute.NewRegistry(contribute.NodeContract{
		NodeID: string(node), Placement: placement,
		Kinds: []contribute.WorkloadKind{contribute.Compute, contribute.Storage},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(echoExecutor{}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(newStorageExecutor()); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCoord{t: t, nodePub: nodePub, coordKey: coordKey,
		reports: map[string]employment.JobReport{}, declines: map[string]employment.Decline{}}
	srv := httptest.NewServer(httpjson.Handler(fc))
	t.Cleanup(srv.Close)

	return &Loop{
		Agent:    NewAgent(reg, ownerActive, nil),
		Coord:    coord.Dial(srv.URL),
		Node:     node,
		Key:      nodeKey,
		CoordKey: coordKey.Public().(ed25519.PublicKey),
		Class:    listing.ClassStandard,
	}, fc
}

func TestLoopLifecycle(t *testing.T) {
	l, fc := harness(t, contribute.Pinned, nil)
	ctx := context.Background()

	if err := l.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := fc.listings[0].OptIn; !got.Compute || got.Print {
		t.Errorf("listing opt-in = %+v, want compute and not print", got)
	}
	for i := 0; i < 3; i++ {
		if err := l.Beat(ctx); err != nil {
			t.Fatalf("Beat %d: %v", i, err)
		}
	}

	shard, _ := json.Marshal(storageOp{Op: "store", ID: "s1", Data: base64.StdEncoding.EncodeToString([]byte("sealed"))})
	fc.assign(l.Node, "c1", "compute", "hello")
	fc.assign(l.Node, "s1", "storage", string(shard))
	fc.assign(l.Node, "p1", "print")
	fc.assign(l.Node, "x1", "mining")
	fc.assign("someone-else", "o1", "compute")

	if err := l.PollOnce(ctx); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	// A second poll sees nothing new and settles nothing twice.
	if err := l.PollOnce(ctx); err != nil {
		t.Fatalf("second PollOnce: %v", err)
	}

	for _, id := range []string{"c1", "s1"} {
		r, ok := fc.reports[id]
		if !ok || r.ExitCode != 0 {
			t.Errorf("job %s: report %+v (present %v), want exit 0", id, r, ok)
		}
	}
	for id, want := range map[string]employment.DeclineReason{
		"p1": employment.DeclineLocalPolicy, // opted out locally
		"x1": employment.DeclineLocalPolicy, // unknown workload
		"o1": employment.DeclineLocalPolicy, // not this node's job
	} {
		if d, ok := fc.declines[id]; !ok || d.Reason != want {
			t.Errorf("job %s: decline %+v (present %v), want %s", id, d, ok, want)
		}
	}
	if fc.beats != 3 || len(fc.listings) != 1 {
		t.Errorf("beats=%d listings=%d, want 3 and 1", fc.beats, len(fc.listings))
	}
}

func TestLoopRefusesForgedAssignment(t *testing.T) {
	l, fc := harness(t, contribute.Pinned, nil)
	_, impostor := genKey(t)
	a := employment.Assignment{JobID: "f1", NodeID: l.Node, Spec: employment.JobSpec{Workload: "compute"}}
	a.Sign(impostor)
	fc.queue = append(fc.queue, a)

	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ran := fc.reports["f1"]; ran {
		t.Fatal("a forged assignment was run")
	}
	if d, ok := fc.declines["f1"]; !ok || d.Reason != employment.DeclineLocalPolicy {
		t.Errorf("forged assignment: decline %+v (present %v), want local_policy", d, ok)
	}
}

func TestLoopOwnerReturns(t *testing.T) {
	var active atomic.Bool
	l, fc := harness(t, contribute.Scavenged, active.Load)
	ctx := context.Background()

	if err := l.List(ctx); err != nil {
		t.Fatal(err)
	}
	active.Store(true)
	// The next heartbeat re-lists the node as offering nothing.
	if err := l.Beat(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(fc.listings); n != 2 {
		t.Fatalf("listings = %d, want a re-listing when the owner returned", n)
	}
	if o := fc.listings[1].OptIn; o.Compute || o.Print {
		t.Errorf("re-listing offers %+v while the owner is active, want nothing", o)
	}
	fc.assign(l.Node, "c2", "compute", "hi")
	if err := l.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if d, ok := fc.declines["c2"]; !ok || d.Reason != employment.DeclineUnavailable {
		t.Errorf("owner active: decline %+v (present %v), want unavailable", d, ok)
	}
	// The owner leaves: the node re-lists and takes work again.
	active.Store(false)
	if err := l.Beat(ctx); err != nil {
		t.Fatal(err)
	}
	if o := fc.listings[len(fc.listings)-1].OptIn; !o.Compute {
		t.Error("node did not re-list its capacity after the owner left")
	}
}

func TestLoopSeqNeverRepeats(t *testing.T) {
	l, _ := harness(t, contribute.Pinned, nil)
	fixed := time.Unix(1700000000, 0)
	l.Now = func() time.Time { return fixed } // a stuck clock
	a, b := l.nextSeq(), l.nextSeq()
	l.Now = func() time.Time { return fixed.Add(-time.Hour) } // a clock that went back
	c := l.nextSeq()
	if !(a < b && b < c) {
		t.Errorf("seq %d, %d, %d: want strictly increasing whatever the clock does", a, b, c)
	}
}

func TestLoopRunKeepsGoingAndStops(t *testing.T) {
	l, fc := harness(t, contribute.Pinned, nil)
	l.Heartbeat, l.Poll = 5*time.Millisecond, 5*time.Millisecond
	fc.assign(l.Node, "c3", "compute", "x")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := l.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v, want it to stop when its context ends", err)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.beats < 3 {
		t.Errorf("beats = %d, want several", fc.beats)
	}
	if _, ok := fc.reports["c3"]; !ok {
		t.Error("Run did not pick up and report queued work")
	}
}

func TestNodeKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	k1, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v (%v), want 0600", info.Mode().Perm(), err)
	}
	k2, err := loadOrCreateKey(path)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("reload gave a different key (%v)", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(path); err == nil {
		t.Error("a key file readable by others was accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(bad, []byte("not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(bad); err == nil {
		t.Error("a malformed key file was accepted")
	}
}

// The agent reaches its orchestrator through its frontend (decision 0001):
// agent → frontend relay → orchestrator. Here the orchestrator is the
// frontend's own, in-process — the case of a platform outside the Antare
// federation — and the full lifecycle still works, with the node's signatures
// intact at the orchestrator and heartbeats rolled up on the way.
func TestLoopThroughFrontendRelay(t *testing.T) {
	l, fc := harness(t, contribute.Pinned, nil)
	ctx := context.Background()

	relay := &noderelay.Relay{Upstream: fc}
	if err := relay.Enroll(ctx, l.Node, l.Key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(relay.Handler())
	defer front.Close()
	l.Coord = coord.DialWith(front.URL, noderelay.NodeAuth(l.Node, l.Key, nil))

	if err := l.List(ctx); err != nil {
		t.Fatalf("List through the frontend: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Beat(ctx); err != nil {
			t.Fatalf("Beat through the frontend: %v", err)
		}
	}
	fc.assign(l.Node, "r1", "compute", "via-frontend")
	fc.assign(l.Node, "r2", "print")
	if err := l.PollOnce(ctx); err != nil {
		t.Fatalf("PollOnce through the frontend: %v", err)
	}
	if r, ok := fc.reports["r1"]; !ok || r.ExitCode != 0 {
		t.Errorf("r1 report at the orchestrator: %+v (present %v)", r, ok)
	}
	if _, ok := fc.declines["r2"]; !ok {
		t.Error("r2 decline did not reach the orchestrator")
	}
	if fc.beats != 1 {
		t.Errorf("orchestrator saw %d heartbeats for 3 inside one window, want 1 (rolled up)", fc.beats)
	}

	// Without the node's request signature the frontend refuses the agent.
	l.Coord = coord.Dial(front.URL)
	if err := l.PollOnce(ctx); err == nil {
		t.Error("the frontend served a node that did not sign its request")
	}
}
