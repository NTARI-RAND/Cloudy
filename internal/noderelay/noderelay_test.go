package noderelay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/employment"
	"github.com/NTARI-RAND/sohocloud-protocol/fees"
	"github.com/NTARI-RAND/sohocloud-protocol/identity"
	"github.com/NTARI-RAND/sohocloud-protocol/listing"
	"github.com/NTARI-RAND/sohocloud-protocol/liveness"
	"github.com/NTARI-RAND/sohocloud-protocol/operator"
	"github.com/NTARI-RAND/sohocloud-protocol/transport/httpjson"

	"github.com/NTARI-RAND/Cloudy/internal/coord"
	"github.com/NTARI-RAND/Cloudy/internal/opcred"
)

// orchestrator is a fake upstream coordinator. It verifies every node message
// against the node keys it was given, as SoHoLINK's adapter does, so a message
// the relay altered would be refused here.
type orchestrator struct {
	t    *testing.T
	keys map[identity.NodeID]ed25519.PublicKey

	mu      sync.Mutex
	calls   map[string]int
	queue   map[identity.NodeID][]employment.Assignment
	settled map[string]bool
}

func newOrchestrator(t *testing.T) *orchestrator {
	return &orchestrator{t: t, keys: map[identity.NodeID]ed25519.PublicKey{},
		calls: map[string]int{}, queue: map[identity.NodeID][]employment.Assignment{}, settled: map[string]bool{}}
}

var errRejected = errors.New("orchestrator rejected")

func (o *orchestrator) count(op string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls[op]
}

func (o *orchestrator) check(op string, node identity.NodeID, ok func(ed25519.PublicKey) bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls[op]++
	pub, known := o.keys[node]
	if !known || !ok(pub) {
		o.t.Errorf("orchestrator: %s from %s does not verify — the relay altered or forged it", op, node)
		return errRejected
	}
	return nil
}

func (o *orchestrator) SubmitListing(_ context.Context, l listing.CapabilityListing) error {
	return o.check("listing", l.NodeID, l.Verify)
}
func (o *orchestrator) Heartbeat(_ context.Context, h liveness.Heartbeat) error {
	return o.check("heartbeat", h.NodeID, h.Verify)
}
func (o *orchestrator) PollJobs(_ context.Context, id identity.NodeID) ([]employment.Assignment, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls["poll"]++
	var out []employment.Assignment
	for _, a := range o.queue[id] {
		if !o.settled[a.JobID] {
			out = append(out, a)
		}
	}
	return out, nil
}
func (o *orchestrator) Decline(_ context.Context, d employment.Decline) error {
	if err := o.check("decline", d.NodeID, d.Verify); err != nil {
		return err
	}
	o.mu.Lock()
	o.settled[d.JobID] = true
	o.mu.Unlock()
	return nil
}
func (o *orchestrator) ReportJob(_ context.Context, r employment.JobReport) error {
	if err := o.check("report", r.NodeID, r.Verify); err != nil {
		return err
	}
	o.mu.Lock()
	o.settled[r.JobID] = true
	o.mu.Unlock()
	return nil
}
func (o *orchestrator) Fees(context.Context) (fees.FeeDeclaration, error) {
	o.mu.Lock()
	o.calls["fees"]++
	o.mu.Unlock()
	return fees.FeeDeclaration{CoordinatorID: "orch"}, nil
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	orch   *orchestrator
	relay  *Relay
	clk    *clock
	relayU string // relay base URL (what nodes dial)
	ks     *opcred.Keyset
	seen   []http.Header // headers the orchestrator received
	seenMu sync.Mutex
}

// newRig wires: node client → relay Handler (httptest) → coord.DialAsOperator
// → orchestrator behind httpjson (httptest), recording what the orchestrator's
// HTTP layer receives.
func newRig(t *testing.T) *rig {
	t.Helper()
	ks, err := opcred.GenerateKeyset()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{orch: newOrchestrator(t), clk: &clock{t: time.Now()}, ks: ks}
	inner := httpjson.Handler(r.orch)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.seenMu.Lock()
		r.seen = append(r.seen, req.Header.Clone())
		r.seenMu.Unlock()
		inner.ServeHTTP(w, req)
	}))
	t.Cleanup(up.Close)
	signer := opcred.NewTransmissionSigner("cloudy", ks)
	operatorAuth := func(req *http.Request) error {
		tx, err := signer.Next()
		if err != nil {
			return err
		}
		req.Header.Set(opcred.OperatorHeaderName, opcred.EncodeOperatorHeader(tx))
		return nil
	}
	r.relay = &Relay{Upstream: coord.DialAsOperator(up.URL, operatorAuth), Now: r.clk.Now}
	front := httptest.NewServer(r.relay.Handler())
	t.Cleanup(front.Close)
	r.relayU = front.URL
	return r
}

// enroll enrolls a node with both the relay and the orchestrator.
func (r *rig) enroll(t *testing.T, node identity.NodeID) ed25519.PrivateKey {
	t.Helper()
	pub, priv := key(t)
	if err := r.relay.Enroll(context.Background(), node, pub); err != nil {
		t.Fatal(err)
	}
	r.orch.mu.Lock()
	r.orch.keys[node] = pub
	r.orch.mu.Unlock()
	return priv
}

func (r *rig) client(node identity.NodeID, priv ed25519.PrivateKey) *coord.Client {
	return coord.DialWith(r.relayU, NodeAuth(node, priv, r.clk.Now))
}

func assign(o *orchestrator, node identity.NodeID, id string) {
	o.mu.Lock()
	o.queue[node] = append(o.queue[node], employment.Assignment{JobID: id, NodeID: node, Spec: employment.JobSpec{Workload: "compute"}})
	o.mu.Unlock()
}

// decodeOperator mirrors the orchestrator's decode of the operator header.
func decodeOperator(t *testing.T, raw string) operator.OperatorTransmission {
	t.Helper()
	jb, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("operator header not base64: %v", err)
	}
	var w struct {
		OperatorID string `json:"operator_id"`
		TsUnixNano int64  `json:"ts_unix_nano"`
		Nonce      string `json:"nonce"`
		Seq        uint64 `json:"seq"`
		Algo       string `json:"algo"`
		Idx0, Idx1 int
		Sig0, Sig1 string
	}
	if err := json.Unmarshal(jb, &w); err != nil {
		t.Fatalf("operator header not JSON: %v", err)
	}
	d := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	return operator.OperatorTransmission{OperatorID: w.OperatorID, TsUnixNano: w.TsUnixNano, Nonce: d(w.Nonce),
		Seq: w.Seq, Algo: w.Algo, Idx0: w.Idx0, Idx1: w.Idx1, Sig0: d(w.Sig0), Sig1: d(w.Sig1)}
}

func TestRelayForwardsUnchangedUnderOperatorCredential(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const node = identity.NodeID("node-a")
	priv := r.enroll(t, node)
	c := r.client(node, priv)

	l := listing.CapabilityListing{NodeID: node, Class: listing.ClassStandard, IssuedAt: time.Now().UTC(), Seq: 1}
	l.Sign(priv)
	h := liveness.Heartbeat{NodeID: node, SentAt: time.Now().UTC(), Seq: 1}
	h.Sign(priv)
	assign(r.orch, node, "j1")
	assign(r.orch, node, "j2")
	if err := c.SubmitListing(ctx, l); err != nil {
		t.Fatalf("listing: %v", err)
	}
	if err := c.Heartbeat(ctx, h); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	jobs, err := c.PollJobs(ctx, node)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("poll: %d jobs, %v", len(jobs), err)
	}
	rep := employment.JobReport{JobID: "j1", NodeID: node}
	rep.Sign(priv)
	dec := employment.Decline{JobID: "j2", NodeID: node, Reason: employment.DeclineCapacity}
	dec.Sign(priv)
	if err := c.ReportJob(ctx, rep); err != nil {
		t.Fatalf("report: %v", err)
	}
	if err := c.Decline(ctx, dec); err != nil {
		t.Fatalf("decline: %v", err)
	}
	if _, err := c.Fees(ctx); err != nil {
		t.Fatalf("fees: %v", err)
	}

	for _, op := range []string{"listing", "heartbeat", "poll", "report", "decline", "fees"} {
		if r.orch.count(op) != 1 {
			t.Errorf("orchestrator saw %s %d times, want 1", op, r.orch.count(op))
		}
	}
	// Every upstream request carries a fresh, valid operator credential, and
	// none carries the node's frontend-local credential.
	r.seenMu.Lock()
	defer r.seenMu.Unlock()
	var lastSeq uint64
	for i, hdr := range r.seen {
		if hdr.Get(NodeAuthHeader) != "" {
			t.Errorf("upstream request %d carries the node's frontend credential", i)
		}
		tx := decodeOperator(t, hdr.Get(opcred.OperatorHeaderName))
		if err := tx.Verify(r.ks.KeyMap()); err != nil {
			t.Errorf("upstream request %d: operator credential does not verify: %v", i, err)
		}
		if tx.Seq <= lastSeq {
			t.Errorf("upstream request %d reuses operator seq %d", i, tx.Seq)
		}
		lastSeq = tx.Seq
	}
}

func TestRelayRollsUpHeartbeats(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const node = identity.NodeID("node-b")
	priv := r.enroll(t, node)
	c := r.client(node, priv)
	beat := func(seq uint64) error {
		h := liveness.Heartbeat{NodeID: node, SentAt: r.clk.Now().UTC(), Seq: seq}
		h.Sign(priv)
		return c.Heartbeat(ctx, h)
	}
	for seq := uint64(1); seq <= 10; seq++ { // ten beats, 5s apart: inside one window
		if err := beat(seq); err != nil {
			t.Fatalf("beat %d: %v", seq, err)
		}
		r.clk.Add(5 * time.Second)
	}
	if n := r.orch.count("heartbeat"); n != 1 {
		t.Fatalf("orchestrator saw %d heartbeats for 10 inside one window, want 1", n)
	}
	r.clk.Add(DefaultUpstreamBeat)
	if err := beat(11); err != nil {
		t.Fatal(err)
	}
	if n := r.orch.count("heartbeat"); n != 2 {
		t.Errorf("orchestrator saw %d heartbeats after the window passed, want 2", n)
	}
	// A replayed heartbeat is refused, never absorbed.
	if err := beat(11); err == nil {
		t.Error("a replayed heartbeat (same Seq) was accepted")
	}
}

func TestRelayCachesPolls(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const node = identity.NodeID("node-c")
	priv := r.enroll(t, node)
	c := r.client(node, priv)
	assign(r.orch, node, "j1")
	assign(r.orch, node, "j2")

	for i := 0; i < 5; i++ {
		jobs, err := c.PollJobs(ctx, node)
		if err != nil || len(jobs) != 2 {
			t.Fatalf("poll %d: %d jobs, %v", i, len(jobs), err)
		}
	}
	if n := r.orch.count("poll"); n != 1 {
		t.Fatalf("orchestrator saw %d polls for 5 inside one window, want 1", n)
	}
	rep := employment.JobReport{JobID: "j1", NodeID: node}
	rep.Sign(priv)
	if err := c.ReportJob(ctx, rep); err != nil {
		t.Fatal(err)
	}
	jobs, _ := c.PollJobs(ctx, node)
	if len(jobs) != 1 || jobs[0].JobID != "j2" {
		t.Errorf("cached poll after reporting j1 = %v, want only j2", jobs)
	}
	r.clk.Add(DefaultUpstreamPoll)
	if _, err := c.PollJobs(ctx, node); err != nil {
		t.Fatal(err)
	}
	if n := r.orch.count("poll"); n != 2 {
		t.Errorf("orchestrator saw %d polls after the window passed, want 2", n)
	}
}

func TestRelayRefusesWhatItCannotVouchFor(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const node = identity.NodeID("node-d")
	priv := r.enroll(t, node)
	_, stranger := key(t)

	// An unknown node cannot use the relay at all.
	if err := r.client("node-unknown", stranger).Heartbeat(ctx, liveness.Heartbeat{NodeID: "node-unknown", Seq: 1}); err == nil {
		t.Error("an unenrolled node was relayed")
	}
	// An enrolled node's request carrying a message signed by another key.
	c := r.client(node, priv)
	forged := listing.CapabilityListing{NodeID: node, Seq: 1}
	forged.Sign(stranger)
	if err := c.SubmitListing(ctx, forged); err == nil {
		t.Error("a forged listing was relayed")
	}
	// Forged job outcomes: a report or decline signed by another key.
	badRep := employment.JobReport{JobID: "x", NodeID: node}
	badRep.Sign(stranger)
	if err := c.ReportJob(ctx, badRep); err == nil {
		t.Error("a forged report was relayed")
	}
	badDec := employment.Decline{JobID: "y", NodeID: node, Reason: employment.DeclineCapacity}
	badDec.Sign(stranger)
	if err := c.Decline(ctx, badDec); err == nil {
		t.Error("a forged decline was relayed")
	}
	// A stale listing Seq.
	ok := listing.CapabilityListing{NodeID: node, Seq: 5}
	ok.Sign(priv)
	if err := c.SubmitListing(ctx, ok); err != nil {
		t.Fatal(err)
	}
	if err := c.SubmitListing(ctx, ok); err == nil {
		t.Error("a replayed listing was relayed")
	}
	if n := r.orch.count("listing"); n != 1 {
		t.Errorf("orchestrator saw %d listings, want only the 1 genuine one", n)
	}
	for _, op := range []string{"heartbeat", "report", "decline"} {
		if n := r.orch.count(op); n != 0 {
			t.Errorf("orchestrator saw %d %s calls, want 0", n, op)
		}
	}
}

func TestRelayNodeAuth(t *testing.T) {
	r := newRig(t)
	const a, b = identity.NodeID("node-a"), identity.NodeID("node-b")
	privA := r.enroll(t, a)
	r.enroll(t, b)
	_, stranger := key(t)

	send := func(method, path, body string, decorate func(*http.Request) error) int {
		req, _ := http.NewRequest(method, r.relayU+path, strings.NewReader(body))
		if decorate != nil {
			if err := decorate(req); err != nil {
				t.Fatal(err)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	beat := func(node identity.NodeID) string {
		b, _ := json.Marshal(liveness.Heartbeat{NodeID: node, Seq: 1})
		return string(b)
	}
	authA := NodeAuth(a, privA, r.clk.Now)

	cases := []struct {
		name     string
		method   string
		path     string
		body     string
		decorate func(*http.Request) error
		want     int
	}{
		{"no credential", "GET", "/v0/jobs?node_id=node-a", "", nil, 401},
		{"signed by a key not enrolled for the node", "GET", "/v0/jobs?node_id=node-a", "", NodeAuth(a, stranger, r.clk.Now), 401},
		{"signed for one path, sent to another", "GET", "/v0/jobs?node_id=node-a", "", func(req *http.Request) error {
			other, _ := http.NewRequest("GET", r.relayU+"/v0/jobs?node_id=node-b", nil)
			if err := authA(other); err != nil {
				return err
			}
			req.Header.Set(NodeAuthHeader, other.Header.Get(NodeAuthHeader))
			return nil
		}, 401},
		{"too old", "GET", "/v0/jobs?node_id=node-a", "", NodeAuth(a, privA, func() time.Time { return r.clk.Now().Add(-3 * time.Minute) }), 401},
		{"node A polls node B's jobs", "GET", "/v0/jobs?node_id=node-b", "", authA, 403},
		{"node A posts a heartbeat naming node B", "POST", "/v0/heartbeat", beat(b), authA, 403},
		{"fees are open", "GET", "/v0/fees", "", nil, 200},
		{"node A polls its own jobs", "GET", "/v0/jobs?node_id=node-a", "", authA, 200},
	}
	for _, tc := range cases {
		if got := send(tc.method, tc.path, tc.body, tc.decorate); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}

	// A captured credential cannot be replayed, even inside the window.
	req, _ := http.NewRequest("GET", r.relayU+"/v0/jobs?node_id=node-a", nil)
	if err := authA(req); err != nil {
		t.Fatal(err)
	}
	captured := req.Header.Get(NodeAuthHeader)
	replay := func(rq *http.Request) error { rq.Header.Set(NodeAuthHeader, captured); return nil }
	if got := send("GET", "/v0/jobs?node_id=node-a", "", replay); got != 200 {
		t.Fatalf("first use of a fresh credential: %d", got)
	}
	if got := send("GET", "/v0/jobs?node_id=node-a", "", replay); got != 401 {
		t.Errorf("replayed credential: status %d, want 401", got)
	}
}

func TestEnrollFirstWriteWins(t *testing.T) {
	var got map[string]string
	var hdr string
	status := http.StatusOK
	orch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/nodes/pubkey" || req.Method != http.MethodPost {
			t.Errorf("enrollment went to %s %s", req.Method, req.URL.Path)
		}
		hdr = req.Header.Get(opcred.OperatorHeaderName)
		_ = json.NewDecoder(req.Body).Decode(&got)
		w.WriteHeader(status)
	}))
	defer orch.Close()
	decorate := func(req *http.Request) error {
		req.Header.Set(opcred.OperatorHeaderName, "operator-credential")
		return nil
	}
	r := &Relay{Upstream: newOrchestrator(t), EnrollUpstream: EnrollViaOrchestrator(orch.URL, decorate)}

	pub, _ := key(t)
	ctx := context.Background()
	if err := r.Enroll(ctx, "node-e", pub); err != nil {
		t.Fatal(err)
	}
	if hdr != "operator-credential" {
		t.Error("key enrollment was not sent under the operator credential")
	}
	if got["node_id"] != "node-e" || got["public_key"] != base64.StdEncoding.EncodeToString(pub) || got["algo"] != "ed25519" || len(got) != 3 {
		t.Errorf("enrollment body = %v, want exactly node_id, public_key and algo", got)
	}
	if err := r.Enroll(ctx, "node-e", pub); err != nil {
		t.Errorf("re-enrolling the same key: %v", err)
	}
	other, _ := key(t)
	if err := r.Enroll(ctx, "node-e", other); !errors.Is(err, ErrKeyConflict) {
		t.Errorf("enrolling a different key = %v, want ErrKeyConflict", err)
	}
	status = http.StatusConflict
	third, _ := key(t)
	if err := r.Enroll(ctx, "node-f", third); !errors.Is(err, ErrKeyConflict) {
		t.Errorf("orchestrator 409 = %v, want ErrKeyConflict", err)
	}
	if err := r.Enroll(ctx, "node-f", third); !errors.Is(err, ErrKeyConflict) {
		t.Error("a node the orchestrator refused was enrolled locally anyway")
	}
}
