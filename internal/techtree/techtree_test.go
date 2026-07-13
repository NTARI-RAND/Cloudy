package techtree

import (
	"crypto/ed25519"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testPlatform = "cloudy-test"

func mustKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func h(b byte) [32]byte {
	var x [32]byte
	for i := range x {
		x[i] = b
	}
	return x
}

func signedClaim(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, kind ClaimKind, seedByte byte) Claim {
	t.Helper()
	c, err := NewClaim(testPlatform, pub, kind, h(seedByte), h(seedByte+1), h(seedByte+2), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return c
}

// --- Claim ---

func TestClaimRoundTripAndTamper(t *testing.T) {
	pub, priv := mustKey(t, 1)
	c := signedClaim(t, pub, priv, KindFact, 10)
	if !c.Verify() {
		t.Fatal("valid claim rejected")
	}
	id := c.ID()
	c.ResultHash[0] ^= 1 // mutate a field after signing
	if c.Verify() {
		t.Fatal("tampered claim verified")
	}
	if c.ID() == id {
		t.Fatal("ID did not change when a signed field changed")
	}
}

func TestClaimRejectsWrongSignerAndBadKind(t *testing.T) {
	pub, _ := mustKey(t, 1)
	_, other := mustKey(t, 2)
	c, err := NewClaim(testPlatform, pub, KindTechnique, h(1), h(2), h(3), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sign(other); err == nil {
		t.Fatal("signing a claim you did not author should fail")
	}
	if _, err := NewClaim(testPlatform, pub, ClaimKind("tomato"), h(1), h(2), h(3), time.Unix(1, 0)); err == nil {
		t.Fatal("unknown claim kind should be rejected (no free-text kind)")
	}
	if _, err := NewClaim("", pub, KindFact, h(1), h(2), h(3), time.Unix(1, 0)); err == nil {
		t.Fatal("empty platform should be rejected (per-platform binding)")
	}
}

// --- Reference + Tree invariants ---

func TestTreeAddAndReferenceInvariants(t *testing.T) {
	tr, err := NewTree(testPlatform)
	if err != nil {
		t.Fatal(err)
	}
	pubA, privA := mustKey(t, 1)
	pubB, privB := mustKey(t, 2)

	fact := signedClaim(t, pubA, privA, KindFact, 10)
	factID, err := tr.AddClaim(fact)
	if err != nil {
		t.Fatalf("add fact: %v", err)
	}
	if _, err := tr.AddClaim(fact); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("re-adding a claim: got %v, want ErrDuplicate", err)
	}

	// B authors a technique that builds on A's fact.
	tech := signedClaim(t, pubB, privB, KindTechnique, 20)
	techID, err := tr.AddClaim(tech)
	if err != nil {
		t.Fatalf("add technique: %v", err)
	}

	// B may draw builds_on FROM its own technique TO the fact.
	edge, err := NewReference(testPlatform, pubB, RefBuildsOn, techID, factID, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.Sign(privB); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.AddReference(edge); err != nil {
		t.Fatalf("valid builds_on edge: %v", err)
	}

	// A cannot draw an edge FROM B's claim (asserter must own From).
	bad, _ := NewReference(testPlatform, pubA, RefCites, techID, factID, time.Unix(3, 0))
	_ = bad.Sign(privA)
	if _, err := tr.AddReference(bad); !errors.Is(err, ErrNotAsserter) {
		t.Fatalf("edge from someone else's claim: got %v, want ErrNotAsserter", err)
	}

	// Edge to a nonexistent claim is rejected.
	ghost, _ := NewReference(testPlatform, pubA, RefCites, factID, ClaimID(h(9)), time.Unix(4, 0))
	_ = ghost.Sign(privA)
	if _, err := tr.AddReference(ghost); !errors.Is(err, ErrUnknownClaim) {
		t.Fatalf("edge to unknown claim: got %v, want ErrUnknownClaim", err)
	}
}

func TestBuildsOnCycleRejectedButContestAllowed(t *testing.T) {
	tr, _ := NewTree(testPlatform)
	pubA, privA := mustKey(t, 1)
	pubB, privB := mustKey(t, 2)
	a := signedClaim(t, pubA, privA, KindFact, 10)
	aID, _ := tr.AddClaim(a)
	b := signedClaim(t, pubB, privB, KindTechnique, 20)
	bID, _ := tr.AddClaim(b)

	// B: b builds_on a.
	e1, _ := NewReference(testPlatform, pubB, RefBuildsOn, bID, aID, time.Unix(2, 0))
	_ = e1.Sign(privB)
	if _, err := tr.AddReference(e1); err != nil {
		t.Fatal(err)
	}
	// A: a builds_on b would close a cycle → rejected.
	e2, _ := NewReference(testPlatform, pubA, RefBuildsOn, aID, bID, time.Unix(3, 0))
	_ = e2.Sign(privA)
	if _, err := tr.AddReference(e2); !errors.Is(err, ErrBuildsOnCycle) {
		t.Fatalf("cyclic builds_on: got %v, want ErrBuildsOnCycle", err)
	}
	// But A may CONTEST b (a contest is a new claim's edge, not cycle-constrained).
	e3, _ := NewReference(testPlatform, pubA, RefContests, aID, bID, time.Unix(4, 0))
	_ = e3.Sign(privA)
	if _, err := tr.AddReference(e3); err != nil {
		t.Fatalf("contest edge should be allowed even against a builds-on relation: %v", err)
	}
	// The contested claim is still present — contest annotates, never erases.
	if _, ok := tr.Claim(bID); !ok {
		t.Fatal("contested claim was removed — contest must not erase")
	}
}

func TestCrossPlatformRejected(t *testing.T) {
	tr, _ := NewTree(testPlatform)
	pub, priv := mustKey(t, 1)
	c, _ := NewClaim("other-platform", pub, KindFact, h(1), h(2), h(3), time.Unix(1, 0))
	_ = c.Sign(priv)
	if _, err := tr.AddClaim(c); !errors.Is(err, ErrWrongPlatform) {
		t.Fatalf("cross-platform claim: got %v, want ErrWrongPlatform", err)
	}
}

// --- Citation weight ---

func TestCitationWeightDistinctAsserterBreakdown(t *testing.T) {
	tr, _ := NewTree(testPlatform)
	pubT, privT := mustKey(t, 1)
	target := signedClaim(t, pubT, privT, KindFact, 10)
	targetID, _ := tr.AddClaim(target)

	// Three distinct members each author a claim and cite the target; one of
	// them cites it twice (two edges) — distinct-asserter counting must fold
	// that to one.
	for i, seed := range []byte{2, 3, 4} {
		pub, priv := mustKey(t, seed)
		c := signedClaim(t, pub, priv, KindTechnique, byte(30+i*5))
		cID, _ := tr.AddClaim(c)
		e, _ := NewReference(testPlatform, pub, RefCites, cID, targetID, time.Unix(int64(10+i), 0))
		_ = e.Sign(priv)
		if _, err := tr.AddReference(e); err != nil {
			t.Fatal(err)
		}
		if seed == 2 { // same member cites again from the same claim (distinct nonce)
			e2, _ := NewReference(testPlatform, pub, RefCites, cID, targetID, time.Unix(99, 0))
			_ = e2.Sign(priv)
			if _, err := tr.AddReference(e2); err != nil {
				t.Fatal(err)
			}
		}
	}
	w := tr.CitationWeight(targetID)
	if w.Cites != 3 {
		t.Fatalf("Cites = %d, want 3 distinct asserters (double-cite folds to one)", w.Cites)
	}
	if w.BuildsOn != 0 || w.Contests != 0 || w.Refutes != 0 || w.Reproduces != 0 {
		t.Fatalf("unexpected non-cite weight: %+v", w)
	}
	// A claim with no inbound edges has a zero weight, not an error.
	if got := tr.CitationWeight(ClaimID(h(200))); got != (Weight{}) {
		t.Fatalf("unknown claim weight = %+v, want zero", got)
	}
}

// --- Chain + replay ---

func TestOpenLogReplayHeadAndTamper(t *testing.T) {
	tr, _ := NewTree(testPlatform)
	pubA, privA := mustKey(t, 1)
	pubB, privB := mustKey(t, 2)
	a := signedClaim(t, pubA, privA, KindFact, 10)
	aID, _ := tr.AddClaim(a)
	b := signedClaim(t, pubB, privB, KindTechnique, 20)
	bID, _ := tr.AddClaim(b)
	e, _ := NewReference(testPlatform, pubB, RefBuildsOn, bID, aID, time.Unix(2, 0))
	_ = e.Sign(privB)
	if _, err := tr.AddReference(e); err != nil {
		t.Fatal(err)
	}

	// Replaying the log reproduces the identical chain head.
	rebuilt, err := OpenLog(testPlatform, tr.Log())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if rebuilt.Head() != tr.Head() {
		t.Fatal("replayed head differs from original — chain is not deterministic")
	}
	if tr.Head() == (Hash{}) {
		t.Fatal("non-empty tree has a zero head")
	}

	// Tamper: flip a byte in the first claim's signature → replay must fail.
	log := tr.Log()
	log[0].Claim.Signature[0] ^= 1
	if _, err := OpenLog(testPlatform, log); err == nil {
		t.Fatal("OpenLog accepted a tampered claim signature")
	}

	// Reorder: a reference before its claims → replay must fail closed.
	reordered := []Item{{Reference: cloneRefPtr(e)}, {Claim: cloneClaimPtr(a)}, {Claim: cloneClaimPtr(b)}}
	if _, err := OpenLog(testPlatform, reordered); !errors.Is(err, ErrUnknownClaim) {
		t.Fatalf("reordered log: got %v, want ErrUnknownClaim", err)
	}
}

// --- No-truth-authority tripwires ---

// certificationPattern matches names that would smell like the network
// certifying a claim TRUE, or collapsing the citation graph into a single
// ranking — both forbidden by Part III ("no truth authority", "no single index
// of what's good"). It deliberately does NOT match "Verify" (ed25519 signature
// verification, legitimate and universal here) nor "Weight"/"CitationWeight"
// (the sanctioned legible breakdown) nor "Refutes"/"Reproduces" (healthy
// contestation) nor "KindFact" (a claim kind, not a fact-check).
var certificationPattern = regexp.MustCompile(`(?i)(certif|istrue|astrue|truth|official|approv|adjudicat|authentic|endorse|verdict|factcheck|score|ranking|rank\b|median|average)`)

func TestNoTruthAuthorityMethodTripwire(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(&Tree{}),
		reflect.TypeOf(&Claim{}),
		reflect.TypeOf(&Reference{}),
		reflect.TypeOf(&Weight{}),
		reflect.TypeOf(&Item{}),
		reflect.TypeOf(new(ClaimKind)),
		reflect.TypeOf(new(RefKind)),
	}
	for _, typ := range types {
		for i := 0; i < typ.NumMethod(); i++ {
			name := typ.Method(i).Name
			if certificationPattern.MatchString(name) {
				t.Errorf("%s has an exported method %q that smells like truth-certification or a single ranking — the commons anchors and weighs claims, it never certifies fact", typ, name)
			}
		}
	}
}

func TestNoTruthAuthorityFunctionTripwire(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			if certificationPattern.MatchString(fn.Name.Name) {
				t.Errorf("%s declares exported func/method %q that smells like truth-certification or ranking — remove it; anchor and weigh, never certify", name, fn.Name.Name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no package source files — the tripwire is not looking at the package")
	}
}
