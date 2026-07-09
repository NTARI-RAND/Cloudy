package covenant

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// --- shared test fixtures -------------------------------------------------

// testKey returns a deterministic ed25519 keypair derived from seed.
func testKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

// testPlatform is the platform every test Book and test member is minted for;
// Book.Record re-derives member IDs under this name when checking the
// ID<->key binding.
const testPlatform = "test-platform"

// testCategory is the category most tests assess under; it is one of the
// LBTAS defaults, so every default-vocabulary test Book accepts it.
const testCategory = "reliability"

// testMember mints a member on the test platform from a deterministic key.
func testMember(seed byte) (MemberID, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv := testKey(seed)
	return MemberIDFor(testPlatform, pub), pub, priv
}

// ref returns a non-zero ExchangeRef filled with b (b must be non-zero for a
// valid reference).
func ref(b byte) ExchangeRef {
	var r ExchangeRef
	for i := range r {
		r[i] = b
	}
	return r
}

// commentHash returns a non-zero [32]byte filled with b, standing in for the
// SHA-256 of a justifying comment held in erasable member-local storage.
func commentHash(b byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return h
}

// testAssessment returns an unsigned, otherwise-valid assessment under
// testCategory. A No Trust (-1) level gets a non-zero CommentHash, as
// Book.Record requires.
func testAssessment(assessor, subject MemberID, ex ExchangeRef, l Level) Assessment {
	a := Assessment{
		Assessor: assessor,
		Subject:  subject,
		Exchange: ex,
		Category: testCategory,
		Level:    l,
		IssuedAt: time.Unix(1700000000, 0).UTC(),
	}
	if l == LevelNoTrust {
		a.CommentHash = commentHash(0xCC)
	}
	return a
}

// dirMap is a test Directory.
type dirMap map[MemberID]ed25519.PublicKey

func (d dirMap) PublicKey(m MemberID) (ed25519.PublicKey, bool) {
	k, ok := d[m]
	return k, ok
}

// sealSet is a test Anchors: a set of sealed (exchange, unordered pair) keys.
type sealSet map[string]struct{}

func pairKey(ex ExchangeRef, a, b MemberID) string {
	if b < a {
		a, b = b, a
	}
	return string(ex[:]) + "\x00" + string(a) + "\x00" + string(b)
}

func (ss sealSet) seal(ex ExchangeRef, a, b MemberID) {
	ss[pairKey(ex, a, b)] = struct{}{}
}

func (ss sealSet) Sealed(ex ExchangeRef, assessor, subject MemberID) bool {
	_, ok := ss[pairKey(ex, assessor, subject)]
	return ok
}

// --- level tests -----------------------------------------------------------

func TestLevelValues(t *testing.T) {
	// The six LBTAS levels carry their spec numeric values.
	cases := []struct {
		level Level
		value int8
		label string
	}{
		{LevelNoTrust, -1, "No Trust"},
		{LevelCynicalSatisfaction, 0, "Cynical Satisfaction"},
		{LevelBasicPromise, 1, "Basic Promise"},
		{LevelBasicSatisfaction, 2, "Basic Satisfaction"},
		{LevelNoNegativeConsequences, 3, "No Negative Consequences"},
		{LevelDelight, 4, "Delight"},
	}
	for _, tc := range cases {
		if int8(tc.level) != tc.value {
			t.Errorf("%s has numeric value %d, want %d", tc.label, int8(tc.level), tc.value)
		}
		if got := tc.level.String(); got != tc.label {
			t.Errorf("Level(%d).String() = %q, want the LBTAS label %q", tc.value, got, tc.label)
		}
		if !validLevel(tc.level) {
			t.Errorf("validLevel(%s) = false, want true", tc.label)
		}
	}
}

func TestLevelValidRejectsOutOfRange(t *testing.T) {
	// validLevel admits exactly the six named levels; adjacent numeric values
	// are out of the scale.
	for _, l := range []Level{Level(5), Level(-2), Level(6), Level(127), Level(-128)} {
		if validLevel(l) {
			t.Errorf("validLevel(%d) = true, want false — the scale has exactly six levels", int8(l))
		}
		if s := l.String(); !strings.Contains(s, "invalid level") {
			t.Errorf("Level(%d).String() = %q, want an invalid-level marker, not an LBTAS label", int8(l), s)
		}
	}
}

func TestLevelsOrder(t *testing.T) {
	// Display order is best-to-worst, +4 down to -1, per the LBTAS output
	// contract for printed distributions.
	want := [6]Level{
		LevelDelight,
		LevelNoNegativeConsequences,
		LevelBasicSatisfaction,
		LevelBasicPromise,
		LevelCynicalSatisfaction,
		LevelNoTrust,
	}
	if got := Levels(); got != want {
		t.Fatalf("Levels() = %v, want %v", got, want)
	}
	// Mutating the returned array must not affect a subsequent call.
	got := Levels()
	got[0] = Level(99)
	if again := Levels(); again != want {
		t.Errorf("Levels() shares state with a previously returned value: got %v after mutation", again)
	}
}

// --- message tests ---------------------------------------------------------

func TestSignVerify(t *testing.T) {
	assessor, pub, priv := testMember(1)
	subject, _, _ := testMember(2)
	otherPub, _ := testKey(3)

	a := testAssessment(assessor, subject, ref(0xAA), LevelBasicPromise)
	a.Sign(priv)

	if !a.Verify(pub) {
		t.Fatal("signed assessment must verify under the assessor's public key")
	}
	if a.Verify(otherPub) {
		t.Error("assessment must not verify under a different key")
	}

	empty := a
	empty.Signature = nil
	if empty.Verify(pub) {
		t.Error("assessment with empty signature must not verify")
	}

	short := a
	short.Signature = a.Signature[:ed25519.SignatureSize-1]
	if short.Verify(pub) {
		t.Error("assessment with wrong-length signature must not verify (length is checked before ed25519.Verify)")
	}
	long := a
	long.Signature = append(append([]byte{}, a.Signature...), 0x00)
	if long.Verify(pub) {
		t.Error("assessment with over-length signature must not verify")
	}
}

func TestTamperMatrix(t *testing.T) {
	assessor, pub, priv := testMember(1)
	subject, _, _ := testMember(2)
	third, _, _ := testMember(3)

	cases := []struct {
		name   string
		mutate func(*Assessment)
	}{
		{"Assessor", func(a *Assessment) { a.Assessor = third }},
		{"Subject", func(a *Assessment) { a.Subject = third }},
		{"Exchange", func(a *Assessment) { a.Exchange[0] ^= 0x01 }},
		{"Category", func(a *Assessment) { a.Category = "support" }},
		{"Level", func(a *Assessment) { a.Level = LevelDelight }},
		{"CommentHash", func(a *Assessment) { a.CommentHash[0] ^= 0x01 }},
		{"IssuedAt", func(a *Assessment) { a.IssuedAt = a.IssuedAt.Add(time.Nanosecond) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := testAssessment(assessor, subject, ref(0xAA), LevelBasicPromise)
			a.CommentHash = commentHash(0x11) // non-zero so the CommentHash tamper case is a real bit-flip
			a.Sign(priv)
			if !a.Verify(pub) {
				t.Fatal("pre-tamper assessment must verify")
			}
			tc.mutate(&a)
			if a.Verify(pub) {
				t.Errorf("assessment tampered in %s must not verify: the field is not under the signature", tc.name)
			}
		})
	}
}

// goldenAssessment is the fixed vector for canonical-bytes stability tests.
func goldenAssessment() Assessment {
	a := Assessment{
		Assessor: MemberID(strings.Repeat("0123456789abcdef", 4)),
		Subject:  MemberID(strings.Repeat("fedcba9876543210", 4)),
		Category: "reliability",
		Level:    LevelBasicSatisfaction,
		IssuedAt: time.Unix(1700000000, 123456789).UTC(),
	}
	for i := range a.Exchange {
		a.Exchange[i] = byte(i + 1)
	}
	for i := range a.CommentHash {
		a.CommentHash[i] = byte(0xC0 + i)
	}
	return a
}

// Independent reconstruction of the canon wire format (SPEC: uvarint length
// prefixes, fixed 8-byte big-endian int64 for level and time), so the golden
// test fails if the encoder's format ever drifts.
func appendUvarint(b []byte, n uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	m := binary.PutUvarint(tmp[:], n)
	return append(b, tmp[:m]...)
}

func appendLenPrefixed(b, p []byte) []byte {
	b = appendUvarint(b, uint64(len(p)))
	return append(b, p...)
}

func appendInt64(b []byte, v int64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(v))
	return append(b, tmp[:]...)
}

// reconstructCanonical rebuilds an assessment's canonical bytes independently
// of canon, in the documented field order: assessor, subject, exchange,
// category, level (Int64), commentHash, issuedAt.
func reconstructCanonical(a Assessment) []byte {
	var want []byte
	want = appendLenPrefixed(want, []byte("cloudy/covenant/assessment/v0"))
	want = appendLenPrefixed(want, []byte(a.Assessor))
	want = appendLenPrefixed(want, []byte(a.Subject))
	want = appendLenPrefixed(want, a.Exchange[:])
	want = appendLenPrefixed(want, []byte(a.Category))
	want = appendInt64(want, int64(a.Level))
	want = appendLenPrefixed(want, a.CommentHash[:])
	want = appendInt64(want, a.IssuedAt.UTC().UnixNano())
	return want
}

func TestCanonicalBytesGolden(t *testing.T) {
	a := goldenAssessment()
	got := a.CanonicalBytes()

	// Byte-exact golden vector, reconstructed independently of canon.
	if want := reconstructCanonical(a); !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes drifted from the golden vector:\n got %x\nwant %x", got, want)
	}

	// Frozen hex of the same vector: fails on ANY change to fields, order,
	// tag, or encoding — including a change mirrored into the reconstruction.
	const goldenHex = "" +
		"1d636c6f7564792f636f76656e616e742f6173736573736d656e742f7630" +
		"4030313233343536373839616263646566303132333435363738396162636465663031323334353637383961626364656630313233343536373839616263646566" +
		"4066656463626139383736353433323130666564636261393837363534333231306665646362613938373635343332313066656463626139383736353433323130" +
		"200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
		"0b72656c696162696c697479" +
		"0000000000000002" +
		"20c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
		"17979cfe3d85cd15"
	if hex.EncodeToString(got) != goldenHex {
		t.Fatalf("canonical bytes drifted from the frozen golden hex:\ngot  %s\nwant %s", hex.EncodeToString(got), goldenHex)
	}

	// The bytes begin with the length-prefixed domain tag.
	tag := "cloudy/covenant/assessment/v0"
	prefix := appendLenPrefixed(nil, []byte(tag))
	if !bytes.HasPrefix(got, prefix) {
		t.Errorf("canonical bytes must begin with the length-prefixed domain tag %q", tag)
	}

	// A non-UTC location must produce identical bytes: canon drops location.
	loc := a
	loc.IssuedAt = a.IssuedAt.In(time.FixedZone("UTC+11", 11*60*60))
	if !bytes.Equal(loc.CanonicalBytes(), got) {
		t.Error("canonical bytes must be identical for the same instant in a non-UTC location")
	}
}

func TestCanonicalBytesNegativeLevel(t *testing.T) {
	// A No Trust (-1) verdict encodes as the 8-byte big-endian two's
	// complement of -1; the independent reconstruction pins that.
	a := goldenAssessment()
	a.Level = LevelNoTrust
	got := a.CanonicalBytes()
	if want := reconstructCanonical(a); !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes for a -1 level drifted from the independent reconstruction:\n got %x\nwant %x", got, want)
	}
	if !bytes.Contains(got, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Error("canonical bytes for level -1 must contain its 8-byte two's-complement encoding ffffffffffffffff")
	}
}

func TestDomainTagReplay(t *testing.T) {
	assessor, pub, priv := testMember(1)
	subject, _, _ := testMember(2)
	a := testAssessment(assessor, subject, ref(0xAA), LevelBasicPromise)

	// Same field sequence under a foreign domain tag.
	foreign := canon.New("sohocloud/listing/v0")
	foreign.String(string(a.Assessor))
	foreign.String(string(a.Subject))
	foreign.Bytes(a.Exchange[:])
	foreign.String(a.Category)
	foreign.Int64(int64(a.Level))
	foreign.Bytes(a.CommentHash[:])
	foreign.Time(a.IssuedAt)
	foreignPayload := foreign.Sum()

	// A signature minted under the foreign tag must not verify as a covenant
	// assessment signature.
	a.Signature = ed25519.Sign(priv, foreignPayload)
	if a.Verify(pub) {
		t.Error("a signature over a foreign-tagged payload must not verify against covenant canonical bytes")
	}

	// And a genuine covenant signature must not verify over the foreign
	// payload: covenant signatures are not transferable to other tags.
	a.Sign(priv)
	if ed25519.Verify(pub, foreignPayload, a.Signature) {
		t.Error("a covenant assessment signature must not verify over a foreign-tagged payload")
	}
}
