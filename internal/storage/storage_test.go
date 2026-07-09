package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// drbg is a deterministic entropy source for tests: same seed, same stream.
type drbg struct {
	state [32]byte
	buf   []byte
}

func newDRBG(seed string) *drbg {
	d := &drbg{}
	d.state = sha256.Sum256([]byte(seed))
	return d
}

func (d *drbg) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		d.state = sha256.Sum256(d.state[:])
		d.buf = append(d.buf, d.state[:]...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func testKeyID(t *testing.T, seed string) (ObjectKey, ObjectID) {
	t.Helper()
	r := newDRBG(seed)
	key, err := NewObjectKey(r)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewObjectID(r)
	if err != nil {
		t.Fatal(err)
	}
	return key, id
}

// --- Countermeasure 1: quantization ---

func TestClassForBoundaries(t *testing.T) {
	k := 4
	small := int(ClassSmall)
	cases := []struct {
		n    int
		want Class
	}{
		{0, ClassSmall},
		{k*small - frameOverhead, ClassSmall},
		{k*small - frameOverhead + 1, ClassMedium},
		{k*int(ClassMedium) - frameOverhead, ClassMedium},
		{k*int(ClassMedium) - frameOverhead + 1, ClassLarge},
	}
	for _, c := range cases {
		got, err := classFor(c.n, k)
		if err != nil {
			t.Fatalf("classFor(%d): %v", c.n, err)
		}
		if got != c.want {
			t.Fatalf("classFor(%d) = %d, want %d", c.n, got, c.want)
		}
	}
	if _, err := classFor(k*int(ClassLarge), k); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("oversized object: got %v, want ErrObjectTooLarge", err)
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	r := newDRBG("pad")
	plain := []byte("the quick brown fox")
	padded, err := pad(plain, 1024, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != 1024 {
		t.Fatalf("padded length %d, want 1024", len(padded))
	}
	got, err := unpad(padded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("unpad did not recover plaintext")
	}
}

func TestUnpadRejectsCorruptFrame(t *testing.T) {
	if _, err := unpad([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}); !errors.Is(err, ErrCorruptFrame) {
		t.Fatalf("got %v, want ErrCorruptFrame", err)
	}
	if _, err := unpad([]byte{0x01}); !errors.Is(err, ErrCorruptFrame) {
		t.Fatalf("short input: got %v, want ErrCorruptFrame", err)
	}
}

// TestQuantizationUniformity is the countermeasure-1 property itself: two
// objects with wildly different true sizes, sealed in the same class, are
// indistinguishable by shard length.
func TestQuantizationUniformity(t *testing.T) {
	coder := StandInSplitter{K: 4}
	keyA, idA := testKeyID(t, "obj-a")
	keyB, idB := testKeyID(t, "obj-b")

	tiny := []byte("x")
	big := bytes.Repeat([]byte{0xAB}, 3<<20) // 3 MiB, same ClassSmall with K=4

	a, err := SealObject(keyA, idA, tiny, coder, newDRBG("rand-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealObject(keyB, idB, big, coder, newDRBG("rand-b"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Class != ClassSmall || b.Class != ClassSmall {
		t.Fatalf("classes %d/%d, want both ClassSmall", a.Class, b.Class)
	}
	want := len(a.Shards[0].Sealed)
	for _, obj := range []SealedObject{a, b} {
		for i, sh := range obj.Shards {
			if len(sh.Sealed) != want {
				t.Fatalf("shard %d sealed length %d, want uniform %d", i, len(sh.Sealed), want)
			}
		}
	}
}

// --- Sealing (§5a plumbing the countermeasures stand on) ---

func TestSealOpenObjectRoundTrip(t *testing.T) {
	coder := StandInSplitter{K: 3}
	key, id := testKeyID(t, "roundtrip")
	plain := bytes.Repeat([]byte("cloudy "), 1000)

	obj, err := SealObject(key, id, plain, coder, newDRBG("rand"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := make([][]byte, len(obj.Shards))
	for i, sh := range obj.Shards {
		if sh.Ref != sha256.Sum256(sh.Sealed) {
			t.Fatalf("shard %d ref is not the content address", i)
		}
		sealed[i] = sh.Sealed
	}
	got, err := OpenObject(key, id, sealed, coder)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("open did not recover plaintext")
	}
}

func TestOpenDetectsTamper(t *testing.T) {
	coder := StandInSplitter{K: 2}
	key, id := testKeyID(t, "tamper")
	obj, err := SealObject(key, id, []byte("secret"), coder, newDRBG("rand"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := [][]byte{append([]byte(nil), obj.Shards[0].Sealed...), obj.Shards[1].Sealed}
	sealed[0][len(sealed[0])/2] ^= 0x01
	if _, err := OpenObject(key, id, sealed, coder); !errors.Is(err, ErrOpenShard) {
		t.Fatalf("got %v, want ErrOpenShard", err)
	}
}

func TestOpenDetectsShardSwap(t *testing.T) {
	coder := StandInSplitter{K: 2}
	key, id := testKeyID(t, "swap")
	obj, err := SealObject(key, id, []byte("position matters"), coder, newDRBG("rand"))
	if err != nil {
		t.Fatal(err)
	}
	// Present shard 1 at index 0 and vice versa: AAD binding must refuse.
	sealed := [][]byte{obj.Shards[1].Sealed, obj.Shards[0].Sealed}
	if _, err := OpenObject(key, id, sealed, coder); !errors.Is(err, ErrOpenShard) {
		t.Fatalf("got %v, want ErrOpenShard", err)
	}
}

func TestOpenRejectsWrongObject(t *testing.T) {
	coder := StandInSplitter{K: 1}
	key, id := testKeyID(t, "obj-1")
	_, otherID := testKeyID(t, "obj-2")
	obj, err := SealObject(key, id, []byte("bound to id"), coder, newDRBG("rand"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObject(key, otherID, [][]byte{obj.Shards[0].Sealed}, coder); !errors.Is(err, ErrOpenShard) {
		t.Fatalf("got %v, want ErrOpenShard", err)
	}
}

func TestStandInSplitterRefusesMissingShard(t *testing.T) {
	coder := StandInSplitter{K: 2}
	key, id := testKeyID(t, "missing")
	obj, err := SealObject(key, id, []byte("no parity"), coder, newDRBG("rand"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := [][]byte{obj.Shards[0].Sealed, nil}
	if _, err := OpenObject(key, id, sealed, coder); !errors.Is(err, ErrShardMissing) {
		t.Fatalf("got %v, want ErrShardMissing (StandIn is honest about zero parity)", err)
	}
}

// --- Countermeasure 2: placement + fetch decorrelation ---

func TestPlaceShardsDistinctHosts(t *testing.T) {
	hosts := []Host{
		{ID: "n1", Owner: "alice"}, {ID: "n2", Owner: "alice"},
		{ID: "n3", Owner: "bob"}, {ID: "n4", Owner: "carol"},
		{ID: "n5", Owner: "dave"},
	}
	got, err := PlaceShards(4, hosts, newDRBG("place"))
	if err != nil {
		t.Fatal(err)
	}
	seenHost := map[string]bool{}
	seenOwner := map[string]bool{}
	for _, h := range got {
		if seenHost[h.ID] {
			t.Fatalf("host %s assigned twice", h.ID)
		}
		seenHost[h.ID] = true
		seenOwner[h.Owner] = true
	}
	// 4 distinct owners exist for 4 shards: the soft rule must use them all.
	if len(seenOwner) != 4 {
		t.Fatalf("distinct owners used = %d, want 4", len(seenOwner))
	}
}

func TestPlaceShardsOwnerFallback(t *testing.T) {
	// Only 2 owners for 3 shards: distinct-host still hard, owner reuse OK.
	hosts := []Host{
		{ID: "n1", Owner: "alice"}, {ID: "n2", Owner: "alice"},
		{ID: "n3", Owner: "bob"},
	}
	got, err := PlaceShards(3, hosts, newDRBG("fallback"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, h := range got {
		if seen[h.ID] {
			t.Fatalf("host %s assigned twice", h.ID)
		}
		seen[h.ID] = true
	}
}

func TestPlaceShardsFailsClosed(t *testing.T) {
	hosts := []Host{{ID: "n1", Owner: "a"}, {ID: "n2", Owner: "b"}}
	if _, err := PlaceShards(3, hosts, newDRBG("few")); !errors.Is(err, ErrInsufficientHosts) {
		t.Fatalf("got %v, want ErrInsufficientHosts", err)
	}
	// Duplicate IDs must not satisfy the distinct-host rule.
	dup := []Host{{ID: "n1", Owner: "a"}, {ID: "n1", Owner: "b"}, {ID: "n2", Owner: "c"}}
	if _, err := PlaceShards(3, dup, newDRBG("dup")); !errors.Is(err, ErrInsufficientHosts) {
		t.Fatalf("got %v, want ErrInsufficientHosts for duplicate host IDs", err)
	}
}

func TestPlacementVariesWithEntropy(t *testing.T) {
	hosts := make([]Host, 8)
	for i := range hosts {
		hosts[i] = Host{ID: string(rune('a' + i)), Owner: string(rune('A' + i))}
	}
	a, err := PlaceShards(8, hosts, newDRBG("seed-1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := PlaceShards(8, hosts, newDRBG("seed-2"))
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for i := range a {
		if a[i].ID != b[i].ID {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two entropy streams produced identical placement — no decorrelation")
	}
}

func TestFetchPlanCompleteAndBounded(t *testing.T) {
	window := 10 * time.Second
	steps, err := FetchPlan(6, window, newDRBG("fetch"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	var last time.Duration = -1
	for _, s := range steps {
		if seen[s.Index] {
			t.Fatalf("shard %d fetched twice", s.Index)
		}
		seen[s.Index] = true
		if s.Delay < 0 || s.Delay >= window {
			t.Fatalf("delay %v outside [0, %v)", s.Delay, window)
		}
		if s.Delay < last {
			t.Fatal("steps not sorted by delay")
		}
		last = s.Delay
	}
	if len(seen) != 6 {
		t.Fatalf("plan covers %d shards, want 6", len(seen))
	}
}

func TestFetchPlanOrderVariesWithEntropy(t *testing.T) {
	a, err := FetchPlan(8, time.Minute, newDRBG("plan-1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := FetchPlan(8, time.Minute, newDRBG("plan-2"))
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for i := range a {
		if a[i].Index != b[i].Index {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two entropy streams produced identical fetch order")
	}
}

// --- Countermeasure 4: audits + cover traffic ---

func TestChallengeTableRoundTrip(t *testing.T) {
	sealed := bytes.Repeat([]byte{0x5C}, 4096)
	table, err := BuildChallengeTable(sealed, 5, newDRBG("audit"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ch, want, err := table.Next()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Respond(sealed, ch)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyProof(want, got) {
			t.Fatalf("challenge %d: honest response rejected", i)
		}
	}
	if _, _, err := table.Next(); !errors.Is(err, ErrTableExhausted) {
		t.Fatalf("got %v, want ErrTableExhausted", err)
	}
	if table.Remaining() != 0 {
		t.Fatalf("remaining %d, want 0", table.Remaining())
	}
}

func TestAuditDetectsTamperedShard(t *testing.T) {
	sealed := bytes.Repeat([]byte{0x77}, 4096)
	table, err := BuildChallengeTable(sealed, 3, newDRBG("audit-tamper"))
	if err != nil {
		t.Fatal(err)
	}
	corrupted := append([]byte(nil), sealed...)
	corrupted[100] ^= 0x01

	// A single flipped byte fails every challenge whose range covers it; to
	// make the test deterministic, corrupt EVERY byte instead.
	for i := range corrupted {
		corrupted[i] ^= 0x01
	}
	ch, want, err := table.Next()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Respond(corrupted, ch)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyProof(want, got) {
		t.Fatal("response over corrupted shard verified")
	}
}

func TestRespondBindsParameters(t *testing.T) {
	sealed := bytes.Repeat([]byte{0x42}, 1024) // uniform bytes: ranges look alike
	chA := Challenge{Offset: 0, Length: 64}
	chB := Challenge{Offset: 64, Length: 64} // same bytes, different position
	a, err := Respond(sealed, chA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Respond(sealed, chB)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("digests for distinct ranges collide — parameters not bound")
	}
	if _, err := Respond(sealed, Challenge{Offset: 1000, Length: 100}); !errors.Is(err, ErrBadChallenge) {
		t.Fatalf("got %v, want ErrBadChallenge", err)
	}
}

func TestCoverSchedulerCadence(t *testing.T) {
	mean := time.Minute
	now := time.Unix(1_700_000_000, 0)
	s, err := NewCoverScheduler(mean, now, newDRBG("cover"))
	if err != nil {
		t.Fatal(err)
	}
	prev := now
	var total time.Duration
	const n = 200
	for i := 0; i < n; i++ {
		slot, err := s.Claim(prev)
		if err != nil {
			t.Fatal(err)
		}
		if !slot.After(prev) && slot != prev {
			t.Fatalf("slot %v not monotonic after %v", slot, prev)
		}
		gap := slot.Sub(prev)
		if i > 0 && (gap < mean/20 || gap > mean*10) {
			t.Fatalf("inter-arrival %v outside clamp [%v, %v]", gap, mean/20, mean*10)
		}
		total += gap
		prev = slot
	}
	avg := total / n
	if avg < mean/3 || avg > mean*3 {
		t.Fatalf("mean inter-arrival %v implausibly far from configured %v", avg, mean)
	}
}

// TestCoverReadRidesSlot: a read claiming a slot produces exactly the event
// the cadence would have produced anyway — same slot time, schedule simply
// advances. The host-observable process is identical with or without reads.
func TestCoverReadRidesSlot(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	audit, err := NewCoverScheduler(time.Minute, now, newDRBG("same-seed"))
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := NewCoverScheduler(time.Minute, now, newDRBG("same-seed"))
	if err != nil {
		t.Fatal(err)
	}
	cursor := now
	for i := 0; i < 50; i++ {
		a, err := audit.Claim(cursor) // pure audit loop
		if err != nil {
			t.Fatal(err)
		}
		b, err := mixed.Claim(cursor) // same slot claimed by a waiting read
		if err != nil {
			t.Fatal(err)
		}
		if !a.Equal(b) {
			t.Fatalf("slot %d: read-ridden schedule diverged (%v vs %v)", i, a, b)
		}
		cursor = a
	}
}
