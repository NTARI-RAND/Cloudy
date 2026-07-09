package covenant

import (
	"crypto/ed25519"
	"encoding/json"
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

// countingStore wraps a Store and counts Appends, so tests can prove the
// gate holds BEFORE anything reaches persistence.
type countingStore struct {
	inner   Store
	appends int
}

func (c *countingStore) Append(ad Admitted) error {
	c.appends++
	return c.inner.Append(ad)
}

func (c *countingStore) BySubject(m MemberID) ([]Admitted, error) {
	return c.inner.BySubject(m)
}

// testBook wires a Book over the given members' keys with the given seals,
// using the LBTAS default category vocabulary.
func testBook(t *testing.T, dir dirMap, seals sealSet, store Store) *Book {
	t.Helper()
	b, err := NewBook(testPlatform, nil, dir, seals, store)
	if err != nil {
		t.Fatalf("NewBook: %v", err)
	}
	return b
}

func TestNewBookRequiresDeps(t *testing.T) {
	dir := dirMap{}
	seals := sealSet{}
	store := NewMemStore()

	cases := []struct {
		name       string
		platform   string
		categories []string
		directory  Directory
		anchors    Anchors
		store      Store
	}{
		{"empty platform", "", nil, dir, seals, store},
		{"nil directory", testPlatform, nil, nil, seals, store},
		{"nil anchors", testPlatform, nil, dir, nil, store},
		{"nil store", testPlatform, nil, dir, seals, nil},
		{"all missing", "", nil, nil, nil, nil},
		{"empty category name", testPlatform, []string{"reliability", ""}, dir, seals, store},
		{"duplicate category", testPlatform, []string{"craft", "craft"}, dir, seals, store},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := NewBook(tc.platform, tc.categories, tc.directory, tc.anchors, tc.store)
			if err == nil {
				t.Fatal("NewBook must return an error on a missing dependency or malformed vocabulary — misconfiguration fails at construction, not at first Record")
			}
			if b != nil {
				t.Error("NewBook must return a nil Book alongside the error")
			}
		})
	}

	// nil categories defaults to the LBTAS four; a custom vocabulary is fine.
	for _, cats := range [][]string{nil, {}, {"craft", "care"}} {
		b, err := NewBook(testPlatform, cats, dir, seals, store)
		if err != nil || b == nil {
			t.Fatalf("NewBook with categories %v = (%v, %v), want a Book and nil error", cats, b, err)
		}
	}
}

func TestRecordRejectsInvalid(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, _ := testMember(2)
	charlie, _, charliePriv := testMember(3) // not in the directory

	dir := dirMap{alice: alicePub, bob: bobPub}
	seals := sealSet{}
	seals.seal(ref(0xAA), alice, bob)
	seals.seal(ref(0xCC), charlie, bob)

	signed := func(a Assessment, priv ed25519.PrivateKey) Assessment {
		a.Sign(priv)
		return a
	}
	withCategory := func(a Assessment, category string) Assessment {
		a.Category = category
		return a
	}
	withoutCommentHash := func(a Assessment) Assessment {
		a.CommentHash = [32]byte{}
		return a
	}

	cases := []struct {
		name string
		a    Assessment
	}{
		{"self-assessment", signed(testAssessment(alice, alice, ref(0xAA), LevelBasicPromise), alicePriv)},
		{"zero exchange ref", signed(testAssessment(alice, bob, ExchangeRef{}, LevelBasicPromise), alicePriv)},
		{"out-of-range level +5", signed(testAssessment(alice, bob, ref(0xAA), Level(5)), alicePriv)},
		{"out-of-range level -2", signed(testAssessment(alice, bob, ref(0xAA), Level(-2)), alicePriv)},
		{"unknown category", signed(withCategory(testAssessment(alice, bob, ref(0xAA), LevelBasicPromise), "warmth"), alicePriv)},
		{"empty category", signed(withCategory(testAssessment(alice, bob, ref(0xAA), LevelBasicPromise), ""), alicePriv)},
		{"no-trust without comment hash", signed(withoutCommentHash(testAssessment(alice, bob, ref(0xAA), LevelNoTrust)), alicePriv)},
		{"zero IssuedAt", signed(Assessment{Assessor: alice, Subject: bob, Exchange: ref(0xAA), Category: testCategory, Level: LevelBasicPromise}, alicePriv)},
		{"unknown assessor key", signed(testAssessment(charlie, bob, ref(0xCC), LevelBasicPromise), charliePriv)},
		{"unsigned", testAssessment(alice, bob, ref(0xAA), LevelBasicPromise)},
		{"signed then tampered", func() Assessment {
			a := signed(testAssessment(alice, bob, ref(0xAA), LevelDelight), alicePriv)
			a.Level = LevelBasicSatisfaction // still a valid level, but no longer what was signed
			return a
		}()},
		{"unanchored exchange", signed(testAssessment(alice, bob, ref(0xBB), LevelBasicPromise), alicePriv)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := &countingStore{inner: NewMemStore()}
			b := testBook(t, dir, seals, cs)
			err := b.Record(tc.a)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Record(%s) = %v, want an error wrapping ErrInvalid", tc.name, err)
			}
			if cs.appends != 0 {
				t.Errorf("Record(%s) reached the Store %d times; the Book is the gate — nothing unverified may reach persistence", tc.name, cs.appends)
			}
		})
	}
}

// TestRecordNoTrustCommentHash pins the LBTAS -1 comment requirement at the
// gate: a No Trust verdict without a justifying CommentHash is rejected
// before persistence, and the same verdict WITH the hash is admitted. For
// levels 0..+4 the hash is optional — present or absent, both admit.
func TestRecordNoTrustCommentHash(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, _ := testMember(2)
	dir := dirMap{alice: alicePub, bob: bobPub}
	seals := sealSet{}
	seals.seal(ref(0xAA), alice, bob)
	seals.seal(ref(0xBB), alice, bob)

	cs := &countingStore{inner: NewMemStore()}
	b := testBook(t, dir, seals, cs)

	// -1 without a comment hash: rejected, with the comment-hash reason.
	bare := testAssessment(alice, bob, ref(0xAA), LevelNoTrust)
	bare.CommentHash = [32]byte{}
	bare.Sign(alicePriv)
	err := b.Record(bare)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Record(-1 without CommentHash) = %v, want an error wrapping ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "CommentHash") {
		t.Errorf("Record(-1 without CommentHash) rejected for %q, want the comment-hash reason", err)
	}
	if cs.appends != 0 {
		t.Fatalf("a -1 without its justifying comment hash reached the Store %d times, want 0", cs.appends)
	}

	// The same -1 with a non-zero hash: admitted.
	justified := testAssessment(alice, bob, ref(0xAA), LevelNoTrust)
	justified.Sign(alicePriv)
	if err := b.Record(justified); err != nil {
		t.Fatalf("Record(-1 with CommentHash) = %v, want nil", err)
	}

	// A +1 with an optional comment hash: also admitted.
	optional := testAssessment(alice, bob, ref(0xBB), LevelBasicPromise)
	optional.CommentHash = commentHash(0x22)
	optional.Sign(alicePriv)
	if err := b.Record(optional); err != nil {
		t.Fatalf("Record(+1 with optional CommentHash) = %v, want nil", err)
	}

	s, err := b.Standing(bob)
	if err != nil {
		t.Fatalf("Standing = %v", err)
	}
	if s.Harm() != 1 {
		t.Errorf("Harm() = %d, want 1 — the admitted -1 must be surfaced", s.Harm())
	}
	if s.Total() != 2 {
		t.Errorf("Total() = %d, want 2", s.Total())
	}
}

// TestRecordCategoryIsClosedVocabulary pins that Category is a selector over
// the Book's fixed set, never free text: the default Book rejects anything
// outside the LBTAS four, and a custom-vocabulary Book rejects the defaults.
func TestRecordCategoryIsClosedVocabulary(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, _ := testMember(2)
	dir := dirMap{alice: alicePub, bob: bobPub}
	seals := sealSet{}
	seals.seal(ref(0xAA), alice, bob)

	custom, err := NewBook(testPlatform, []string{"craft", "care"}, dir, seals, NewMemStore())
	if err != nil {
		t.Fatalf("NewBook(custom categories) = %v", err)
	}

	// "reliability" is not in the custom vocabulary.
	a := testAssessment(alice, bob, ref(0xAA), LevelBasicPromise)
	a.Sign(alicePriv)
	if err := custom.Record(a); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Record(default category on custom Book) = %v, want ErrInvalid", err)
	} else if !strings.Contains(err.Error(), "closed vocabulary") {
		t.Errorf("rejection reason = %q, want the closed-vocabulary reason", err)
	}

	// A vocabulary member is admitted.
	a.Category = "craft"
	a.Sign(alicePriv)
	if err := custom.Record(a); err != nil {
		t.Fatalf("Record(vocabulary category) = %v, want nil", err)
	}
}

// TestRecordRejectsUnmintedMemberIDShape proves validMemberID is a live gate,
// not shadowed by a later one. Each malformed ID is fully provisioned — it is
// registered in the test directory under a real signing key AND sealed into
// the exchange — so every later gate would have to speak for itself, and the
// asserted "not a minted member ID" reason can only come from the ID-shape
// check. Deleting validMemberID turns these cases red.
func TestRecordRejectsUnmintedMemberIDShape(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, _ := testMember(2)
	upper := MemberID("ABCDEF" + string(alice[6:])) // 64 chars, but uppercase hex

	cases := []struct {
		name     string
		assessor MemberID
		subject  MemberID
	}{
		{"human-chosen assessor", "alice", bob},
		{"human-chosen subject", alice, "bob"},
		{"uppercase-hex assessor", upper, bob},
		{"uppercase-hex subject", alice, MemberID("ABCDEF" + string(bob[6:]))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Provision the malformed IDs as if they were real members: the
			// directory answers for them with the genuine keys, and the
			// exchange is sealed between exactly this pair.
			dir := dirMap{tc.assessor: alicePub, tc.subject: bobPub}
			seals := sealSet{}
			seals.seal(ref(0xAA), tc.assessor, tc.subject)
			cs := &countingStore{inner: NewMemStore()}
			b := testBook(t, dir, seals, cs)

			a := testAssessment(tc.assessor, tc.subject, ref(0xAA), LevelBasicPromise)
			a.Sign(alicePriv)
			err := b.Record(a)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Record(%s) = %v, want an error wrapping ErrInvalid", tc.name, err)
			}
			if !strings.Contains(err.Error(), "not a minted member ID") {
				t.Errorf("Record(%s) rejected for %q, want the ID-shape reason (\"not a minted member ID\") — a later gate must not be the one doing the rejecting", tc.name, err)
			}
			if cs.appends != 0 {
				t.Errorf("Record(%s) reached the Store %d times, want 0", tc.name, cs.appends)
			}
		})
	}
}

// TestRecordRejectsRemappedIdentity proves the ID<->key binding is
// re-verified at every admission: a dishonest Directory that remaps an
// accrued MemberID onto a new key must not let the new key holder speak as —
// or be spoken about as — the old identity. Standing follows the ID string,
// so without this gate the remap inherits the accrual.
func TestRecordRejectsRemappedIdentity(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, _ := testMember(2)
	_, malloryPub, malloryPriv := testMember(3)

	t.Run("assessor ID remapped to a new key", func(t *testing.T) {
		// The directory answers for alice's MemberID with mallory's key, and
		// mallory signs — so the signature VERIFIES under the directory's key.
		// Only re-deriving MemberIDFor(platform, key) catches the remap.
		dir := dirMap{alice: malloryPub, bob: bobPub}
		seals := sealSet{}
		seals.seal(ref(0xAA), alice, bob)
		cs := &countingStore{inner: NewMemStore()}
		b := testBook(t, dir, seals, cs)

		a := testAssessment(alice, bob, ref(0xAA), LevelDelight)
		a.Sign(malloryPriv)
		err := b.Record(a)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("Record under a remapped assessor identity = %v, want an error wrapping ErrInvalid", err)
		}
		if !strings.Contains(err.Error(), "does not mint the assessor's member ID") {
			t.Errorf("Record rejected for %q, want the ID<->key binding reason", err)
		}
		if cs.appends != 0 {
			t.Errorf("remapped assessor reached the Store %d times, want 0", cs.appends)
		}
	})

	t.Run("subject ID remapped to a new key", func(t *testing.T) {
		// alice's verdict is genuine, but the directory answers for bob's
		// MemberID with mallory's key: the subject named in the signed bytes
		// is no longer the member the directory says it is.
		dir := dirMap{alice: alicePub, bob: malloryPub}
		seals := sealSet{}
		seals.seal(ref(0xAA), alice, bob)
		cs := &countingStore{inner: NewMemStore()}
		b := testBook(t, dir, seals, cs)

		a := testAssessment(alice, bob, ref(0xAA), LevelBasicPromise)
		a.Sign(alicePriv)
		err := b.Record(a)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("Record under a remapped subject identity = %v, want an error wrapping ErrInvalid", err)
		}
		if !strings.Contains(err.Error(), "does not mint the subject's member ID") {
			t.Errorf("Record rejected for %q, want the ID<->key binding reason", err)
		}
		if cs.appends != 0 {
			t.Errorf("remapped subject reached the Store %d times, want 0", cs.appends)
		}
	})

	t.Run("unknown subject key", func(t *testing.T) {
		// The subject must resolve in the directory at all: an ID with no key
		// cannot have its binding verified, so it cannot accrue standing.
		dir := dirMap{alice: alicePub}
		seals := sealSet{}
		seals.seal(ref(0xAA), alice, bob)
		cs := &countingStore{inner: NewMemStore()}
		b := testBook(t, dir, seals, cs)

		a := testAssessment(alice, bob, ref(0xAA), LevelBasicPromise)
		a.Sign(alicePriv)
		err := b.Record(a)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("Record with an unresolvable subject = %v, want an error wrapping ErrInvalid", err)
		}
		if !strings.Contains(err.Error(), "unknown subject key") {
			t.Errorf("Record rejected for %q, want the unknown-subject-key reason", err)
		}
		if cs.appends != 0 {
			t.Errorf("unresolvable subject reached the Store %d times, want 0", cs.appends)
		}
	})
}

func TestAnchoringIsMemberExact(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, _ := testMember(2)
	carol, carolPub, _ := testMember(3)
	dave, davePub, _ := testMember(4)

	dir := dirMap{alice: alicePub, bob: bobPub, carol: carolPub, dave: davePub}
	seals := sealSet{}
	seals.seal(ref(0xAA), carol, dave) // sealed, but not between alice and bob
	seals.seal(ref(0xBB), alice, carol)

	cs := &countingStore{inner: NewMemStore()}
	b := testBook(t, dir, seals, cs)

	// Sealed exchange, wrong pair entirely.
	a := testAssessment(alice, bob, ref(0xAA), LevelBasicPromise)
	a.Sign(alicePriv)
	if err := b.Record(a); !errors.Is(err, ErrInvalid) {
		t.Errorf("Record over someone else's sealed exchange = %v, want ErrInvalid — no rating strangers off someone else's exchange", err)
	}

	// Sealed exchange involving the assessor, but not the subject.
	a = testAssessment(alice, bob, ref(0xBB), LevelBasicPromise)
	a.Sign(alicePriv)
	if err := b.Record(a); !errors.Is(err, ErrInvalid) {
		t.Errorf("Record over an exchange sealed with a different counterparty = %v, want ErrInvalid", err)
	}

	if cs.appends != 0 {
		t.Errorf("member-inexact anchoring reached the Store %d times, want 0", cs.appends)
	}
}

func TestRecordDuplicate(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, bobPriv := testMember(2)

	dir := dirMap{alice: alicePub, bob: bobPub}
	seals := sealSet{}
	seals.seal(ref(0xAA), alice, bob)
	seals.seal(ref(0xBB), alice, bob)

	b := testBook(t, dir, seals, NewMemStore())

	first := testAssessment(alice, bob, ref(0xAA), LevelBasicPromise)
	first.Sign(alicePriv)
	if err := b.Record(first); err != nil {
		t.Fatalf("first Record = %v, want nil", err)
	}

	// Same (assessor, exchange, category): rejected forever, even at another level.
	again := testAssessment(alice, bob, ref(0xAA), LevelDelight)
	again.Sign(alicePriv)
	if err := b.Record(again); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Record for the same (assessor, exchange, category) = %v, want ErrDuplicate", err)
	}

	// The same (assessor, exchange) under a DIFFERENT category is a distinct
	// verdict slot: uniqueness is the triple, not the pair.
	other := testAssessment(alice, bob, ref(0xAA), LevelBasicSatisfaction)
	other.Category = "support"
	other.Sign(alicePriv)
	if err := b.Record(other); err != nil {
		t.Fatalf("Record under a second category on the same exchange = %v, want nil — uniqueness is (assessor, exchange, category)", err)
	}

	// But that new category slot is itself single-use.
	otherDup := testAssessment(alice, bob, ref(0xAA), LevelDelight)
	otherDup.Category = "support"
	otherDup.Sign(alicePriv)
	if err := b.Record(otherDup); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate within the second category = %v, want ErrDuplicate", err)
	}

	// A different assessor on the same exchange and category is a distinct verdict.
	back := testAssessment(bob, alice, ref(0xAA), LevelBasicSatisfaction)
	back.Sign(bobPriv)
	if err := b.Record(back); err != nil {
		t.Errorf("counterparty Record on the same exchange = %v, want nil — assessment is bidirectional", err)
	}

	// The same assessor on a different sealed exchange is legitimate: repeat
	// exchanges between the same pair each ground one verdict per category.
	second := testAssessment(alice, bob, ref(0xBB), LevelBasicSatisfaction)
	second.Sign(alicePriv)
	if err := b.Record(second); err != nil {
		t.Fatalf("Record on a second sealed exchange = %v, want nil", err)
	}

	s, err := b.Standing(bob)
	if err != nil {
		t.Fatalf("Standing = %v", err)
	}
	if s.Total() != 3 {
		t.Errorf("Standing(bob).Total() = %d, want 3", s.Total())
	}
	if got := s.Category(testCategory).Total(); got != 2 {
		t.Errorf("Category(%q).Total() = %d, want 2", testCategory, got)
	}
	if got := s.Category("support").Total(); got != 1 {
		t.Errorf("Category(\"support\").Total() = %d, want 1", got)
	}
	if s.Overall().Count(LevelBasicPromise) != 1 || s.Overall().Count(LevelBasicSatisfaction) != 2 {
		t.Errorf("Overall() counts = basic-promise %d, basic-satisfaction %d; want 1, 2",
			s.Overall().Count(LevelBasicPromise), s.Overall().Count(LevelBasicSatisfaction))
	}
}

// standingFixture records, for each of two subjects, four assessments from
// four distinct assessors over four distinct sealed exchanges, one per LBTAS
// default category.
func standingFixture(t *testing.T) (*Book, Store, MemberID, MemberID) {
	t.Helper()

	steady, steadyPub, _ := testMember(0x10)     // all Basic Satisfaction
	volatile, volatilePub, _ := testMember(0x20) // half No Trust, half Delight

	dir := dirMap{steady: steadyPub, volatile: volatilePub}
	seals := sealSet{}
	store := NewMemStore()

	type verdict struct {
		subject  MemberID
		category string
		level    Level
	}
	verdicts := []verdict{
		{steady, "reliability", LevelBasicSatisfaction},
		{steady, "usability", LevelBasicSatisfaction},
		{steady, "performance", LevelBasicSatisfaction},
		{steady, "support", LevelBasicSatisfaction},
		{volatile, "reliability", LevelNoTrust},
		{volatile, "usability", LevelDelight},
		{volatile, "performance", LevelDelight},
		{volatile, "support", LevelNoTrust},
	}

	b := testBook(t, dir, seals, store)
	for i, v := range verdicts {
		assessor, pub, priv := testMember(byte(0x80 + i))
		dir[assessor] = pub
		ex := ref(byte(1 + i))
		seals.seal(ex, assessor, v.subject)
		a := Assessment{
			Assessor: assessor,
			Subject:  v.subject,
			Exchange: ex,
			Category: v.category,
			Level:    v.level,
			IssuedAt: time.Unix(1700000000+int64(i), 0).UTC(),
		}
		if v.level == LevelNoTrust {
			a.CommentHash = commentHash(byte(0xC0 + i))
		}
		a.Sign(priv)
		if err := b.Record(a); err != nil {
			t.Fatalf("Record #%d = %v", i, err)
		}
	}
	return b, store, steady, volatile
}

func TestStandingShape(t *testing.T) {
	b, _, steady, volatile := standingFixture(t)

	wantSteady := map[Level]int{LevelBasicSatisfaction: 4}
	wantVolatile := map[Level]int{LevelNoTrust: 2, LevelDelight: 2}
	wantSteadyByCat := map[string]Level{
		"reliability": LevelBasicSatisfaction, "usability": LevelBasicSatisfaction,
		"performance": LevelBasicSatisfaction, "support": LevelBasicSatisfaction,
	}
	wantVolatileByCat := map[string]Level{
		"reliability": LevelNoTrust, "usability": LevelDelight,
		"performance": LevelDelight, "support": LevelNoTrust,
	}

	for _, sub := range []struct {
		name    string
		subject MemberID
		want    map[Level]int
		byCat   map[string]Level
		harm    int
	}{
		{"steady", steady, wantSteady, wantSteadyByCat, 0},
		{"volatile", volatile, wantVolatile, wantVolatileByCat, 2},
	} {
		s, err := b.Standing(sub.subject)
		if err != nil {
			t.Fatalf("Standing(%s) = %v", sub.name, err)
		}
		if s.Total() != 4 {
			t.Errorf("Standing(%s).Total() = %d, want 4", sub.name, s.Total())
		}
		for _, l := range Levels() {
			if got := s.Overall().Count(l); got != sub.want[l] {
				t.Errorf("Standing(%s).Overall().Count(%s) = %d, want %d", sub.name, l, got, sub.want[l])
			}
		}
		for cat, lvl := range sub.byCat {
			d := s.Category(cat)
			if d.Total() != 1 || d.Count(lvl) != 1 {
				t.Errorf("Standing(%s).Category(%q) = total %d, %s %d; want 1, 1", sub.name, cat, d.Total(), lvl, d.Count(lvl))
			}
		}
		if got := s.Harm(); got != sub.harm {
			t.Errorf("Standing(%s).Harm() = %d, want %d — Harm counts every No Trust verdict across all categories", sub.name, got, sub.harm)
		}
		if s.Overall().Count(Level(99)) != 0 {
			t.Errorf("Count of an unknown level must be 0")
		}
		if d := s.Category("no-such-category"); d.Total() != 0 {
			t.Errorf("Category of an unknown name must be empty, got total %d", d.Total())
		}
	}

	// Both subjects sit at the same notional midpoint (all +2 vs half -1 /
	// half +4), but their shapes differ — the shape an average would erase IS
	// the signal, and the volatile subject's two -1s stay individually visible.
	ds, _ := b.Standing(steady)
	dv, _ := b.Standing(volatile)
	same := true
	for _, l := range Levels() {
		if ds.Overall().Count(l) != dv.Overall().Count(l) {
			same = false
		}
	}
	if same {
		t.Error("the two subjects' distributions must differ: an average would conflate them, the distribution must not")
	}
}

// TestStandingCategoryOverallConsistency pins the view contract: Overall is
// the pool of the per-category distributions — every verdict counted once,
// under exactly one category — and Total/Harm agree with both views.
func TestStandingCategoryOverallConsistency(t *testing.T) {
	b, _, steady, volatile := standingFixture(t)
	categories := []string{"reliability", "usability", "performance", "support"}

	for _, subject := range []MemberID{steady, volatile} {
		s, err := b.Standing(subject)
		if err != nil {
			t.Fatalf("Standing = %v", err)
		}
		for _, l := range Levels() {
			pooled := 0
			for _, cat := range categories {
				pooled += s.Category(cat).Count(l)
			}
			if got := s.Overall().Count(l); got != pooled {
				t.Errorf("Overall().Count(%s) = %d, want %d — the per-category counts pooled", l, got, pooled)
			}
		}
		pooledTotal := 0
		for _, cat := range categories {
			pooledTotal += s.Category(cat).Total()
		}
		if s.Overall().Total() != pooledTotal || s.Total() != pooledTotal {
			t.Errorf("Total() = %d, Overall().Total() = %d, want the pooled per-category total %d",
				s.Total(), s.Overall().Total(), pooledTotal)
		}
		if s.Harm() != s.Overall().Count(LevelNoTrust) {
			t.Errorf("Harm() = %d, want Overall().Count(LevelNoTrust) = %d — Harm is the -1 count, nothing else",
				s.Harm(), s.Overall().Count(LevelNoTrust))
		}
	}
}

func TestStandingLossless(t *testing.T) {
	b, store, _, volatile := standingFixture(t)

	ads, err := store.BySubject(volatile)
	if err != nil {
		t.Fatalf("BySubject = %v", err)
	}
	recount := map[Level]int{}
	recountByCat := map[string]map[Level]int{}
	for _, ad := range ads {
		a := ad.Assessment()
		recount[a.Level]++
		if recountByCat[a.Category] == nil {
			recountByCat[a.Category] = map[Level]int{}
		}
		recountByCat[a.Category][a.Level]++
	}

	s, err := b.Standing(volatile)
	if err != nil {
		t.Fatalf("Standing = %v", err)
	}
	if s.Total() != len(ads) {
		t.Errorf("Total() = %d, want the store multiset size %d", s.Total(), len(ads))
	}
	for _, l := range Levels() {
		if s.Overall().Count(l) != recount[l] {
			t.Errorf("Overall().Count(%s) = %d, want %d from the store multiset — the Distribution must be the full distribution, not a summary", l, s.Overall().Count(l), recount[l])
		}
		for cat, want := range recountByCat {
			if got := s.Category(cat).Count(l); got != want[l] {
				t.Errorf("Category(%q).Count(%s) = %d, want %d from the store multiset", cat, l, got, want[l])
			}
		}
	}
}

func TestStandingUnknownMember(t *testing.T) {
	b, _, _, _ := standingFixture(t)
	never, _, _ := testMember(0x77)

	s, err := b.Standing(never)
	if err != nil {
		t.Fatalf("Standing of a never-assessed member = %v, want nil error", err)
	}
	if s.Total() != 0 {
		t.Errorf("Total() = %d, want 0", s.Total())
	}
	if s.Harm() != 0 {
		t.Errorf("Harm() = %d, want 0", s.Harm())
	}
	for _, l := range Levels() {
		if s.Overall().Count(l) != 0 {
			t.Errorf("Overall().Count(%s) = %d, want 0", l, s.Overall().Count(l))
		}
	}
	for _, cat := range []string{"reliability", "usability", "performance", "support"} {
		if d := s.Category(cat); d.Total() != 0 {
			t.Errorf("Category(%q).Total() = %d, want 0", cat, d.Total())
		}
	}
}

// hostileStore violates the Store contract: BySubject ignores its argument
// and replays every appended verdict three times, no matter who is queried.
// It stands in for a compromised or buggy persistence layer — the class of
// dependency Standing must not extend trust to.
type hostileStore struct {
	replay []Admitted
}

func (h *hostileStore) Append(ad Admitted) error {
	h.replay = append(h.replay, ad)
	return nil
}

func (h *hostileStore) BySubject(MemberID) ([]Admitted, error) {
	out := make([]Admitted, 0, 3*len(h.replay))
	for i := 0; i < 3; i++ {
		out = append(out, h.replay...)
	}
	return out, nil
}

// TestStandingDoesNotTrustTheStore proves Standing re-validates the SIGNED
// data instead of trusting the Store's indexing: a hostile store must not be
// able to re-attribute standing to the wrong member or inflate one verdict
// into three — reputation would become mintable by the persistence layer,
// which is the not-currency invariant broken.
func TestStandingDoesNotTrustTheStore(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)
	bob, bobPub, _ := testMember(2)
	carol, _, _ := testMember(3)

	dir := dirMap{alice: alicePub, bob: bobPub}
	seals := sealSet{}
	seals.seal(ref(0xAA), alice, bob)
	hs := &hostileStore{}
	b := testBook(t, dir, seals, hs)

	// One genuine, fully admitted alice -> bob Delight verdict.
	a := testAssessment(alice, bob, ref(0xAA), LevelDelight)
	a.Sign(alicePriv)
	if err := b.Record(a); err != nil {
		t.Fatalf("Record = %v", err)
	}

	// Re-attribution: querying carol, the store hands back bob's verdicts.
	// Standing must surface the contract violation, never credit carol.
	if _, err := b.Standing(carol); err == nil {
		t.Error("Standing(carol) over a store returning bob's assessments = nil error, want an error naming the store contract violation — standing must never be re-attributed")
	} else if !strings.Contains(err.Error(), "store contract violation") {
		t.Errorf("Standing(carol) = %v, want an error naming the store contract violation", err)
	}

	// Inflation: the store replays bob's one verdict three times. One signed
	// (Assessor, Exchange, Category) verdict is one verdict, however often it
	// echoes.
	s, err := b.Standing(bob)
	if err != nil {
		t.Fatalf("Standing(bob) = %v", err)
	}
	if s.Total() != 1 || s.Overall().Count(LevelDelight) != 1 {
		t.Errorf("Standing(bob) over a replaying store = total %d, delight %d; want 1, 1 — a store replay must not inflate standing", s.Total(), s.Overall().Count(LevelDelight))
	}
	if got := s.Category(testCategory).Count(LevelDelight); got != 1 {
		t.Errorf("Category(%q).Count(Delight) = %d, want 1", testCategory, got)
	}
}

// replayStore is a permissive Store with no uniqueness enforcement: it
// returns exactly what was appended, duplicates and all. It exists to prove
// Standing's OWN dedup is keyed (assessor, exchange, category) — independent
// of the Store's.
type replayStore struct {
	ads []Admitted
}

func (r *replayStore) Append(ad Admitted) error {
	r.ads = append(r.ads, ad)
	return nil
}

func (r *replayStore) BySubject(subject MemberID) ([]Admitted, error) {
	out := make([]Admitted, 0, len(r.ads))
	for _, ad := range r.ads {
		if ad.Assessment().Subject == subject {
			out = append(out, ad)
		}
	}
	return out, nil
}

// TestStandingDedupIsPerCategory pins the read-side dedup key: the same
// (assessor, exchange) under two categories is two verdicts, while a replay
// of one (assessor, exchange, category) triple is one — even when the Store
// fails to enforce uniqueness itself.
func TestStandingDedupIsPerCategory(t *testing.T) {
	alice, _, _ := testMember(1)
	bob, _, _ := testMember(2)

	rs := &replayStore{}
	// Bypass Record and mint directly (test-only): the permissive store holds
	// a same-triple replay plus a second category on the same exchange.
	rs.ads = append(rs.ads,
		admitted(alice, bob, ref(0xAA), "reliability", LevelBasicPromise, nil),
		admitted(alice, bob, ref(0xAA), "reliability", LevelBasicPromise, nil), // same triple: must count once
		admitted(alice, bob, ref(0xAA), "support", LevelDelight, nil),          // same pair, new category: distinct verdict
	)
	b := testBook(t, dirMap{}, sealSet{}, rs)

	s, err := b.Standing(bob)
	if err != nil {
		t.Fatalf("Standing = %v", err)
	}
	if s.Total() != 2 {
		t.Errorf("Total() = %d, want 2 — one per (assessor, exchange, category) triple", s.Total())
	}
	if got := s.Category("reliability").Total(); got != 1 {
		t.Errorf("Category(reliability).Total() = %d, want 1 — the same-triple replay must be counted once", got)
	}
	if got := s.Category("support").Total(); got != 1 {
		t.Errorf("Category(support).Total() = %d, want 1 — a second category is a distinct verdict slot", got)
	}
}

func TestStandingNotSerializable(t *testing.T) {
	b, _, _, volatile := standingFixture(t)
	s, err := b.Standing(volatile)
	if err != nil {
		t.Fatalf("Standing = %v", err)
	}
	if s.Total() == 0 {
		t.Fatal("fixture must yield a populated Standing")
	}
	for name, v := range map[string]interface{}{
		"Standing":     s,
		"Distribution": s.Overall(),
	} {
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal(%s) = %v", name, err)
		}
		if string(out) != "{}" {
			t.Errorf("json.Marshal of a populated %s = %s, want {} — no export format may leak as a side effect", name, out)
		}
	}
}

// collapsePattern matches names that smell like a collapse of the
// distribution into a number. Shared by the reflection tripwire (method sets)
// and the go/ast tripwire (package-level source scan).
var collapsePattern = regexp.MustCompile(`(?i)(mean|avg|average|score|sum|median|percentile|compare|rank|rating|grade|weight|scalar|numeric)`)

func TestNoCollapseTripwire(t *testing.T) {
	// Pointer types only: a pointer type's method set is the SUPERSET of the
	// value type's (value receivers plus pointer receivers), so a
	// pointer-receiver collapse method — e.g. func (d *Distribution) Mean() —
	// cannot hide from this tripwire the way it could hide from
	// reflect.TypeOf(Distribution{}).
	types := []reflect.Type{
		reflect.TypeOf(&Distribution{}),
		reflect.TypeOf(&Standing{}),
		reflect.TypeOf(&Book{}),
		reflect.TypeOf(&Admitted{}),
		reflect.TypeOf(&MemStore{}),
		reflect.TypeOf(new(Level)),
	}
	for _, typ := range types {
		for i := 0; i < typ.NumMethod(); i++ {
			name := typ.Method(i).Name
			if collapsePattern.MatchString(name) {
				t.Errorf("%s has a collapse-named exported method %q: reputation is a distribution, never a score — remove it", typ, name)
			}
		}
	}
}

// TestNoCollapseFunctionTripwire closes the reflection tripwire's blind spot:
// reflection only sees method sets, so a package-level func AverageStanding(…)
// would ship with TestNoCollapseTripwire green. Scanning the package SOURCE
// with go/ast catches every exported func and method declaration in the
// shipped (non-test) files, whatever its receiver.
func TestNoCollapseFunctionTripwire(t *testing.T) {
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
			if collapsePattern.MatchString(fn.Name.Name) {
				t.Errorf("%s declares a collapse-named exported function or method %q: reputation is a distribution, never a score — remove it", name, fn.Name.Name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no package source files — the tripwire is not looking at the package")
	}
}

// hostileZeroStore returns a zero-value Admitted for every query and counts
// how often it is consulted, so tests can prove a guard runs before the
// Store is trusted with anything.
type hostileZeroStore struct{ queried int }

func (h *hostileZeroStore) Append(Admitted) error { return nil }
func (h *hostileZeroStore) BySubject(MemberID) ([]Admitted, error) {
	h.queried++
	return []Admitted{{}}, nil
}

// TestStandingRejectsUnmintedSubject pins the read-side shape guard: only
// MemberIDFor mints IDs (always 64 lowercase hex), so an unmintable subject
// can have no standing, and querying one must not give a hostile Store a hook
// to attach phantom entries to it.
func TestStandingRejectsUnmintedSubject(t *testing.T) {
	alice, alicePub, _ := testMember(1)
	hostile := &hostileZeroStore{}
	b := testBook(t, dirMap{alice: alicePub}, sealSet{}, hostile)

	for _, subject := range []MemberID{"", "bob", MemberID(strings.ToUpper(string(alice)))} {
		s, err := b.Standing(subject)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("Standing(%q) error = %v, want ErrInvalid", subject, err)
		}
		if s.Total() != 0 {
			t.Errorf("Standing(%q) counted %d phantom entries, want 0", subject, s.Total())
		}
	}
	if hostile.queried != 0 {
		t.Errorf("hostile store was queried %d times; the shape guard must run before the Store is consulted", hostile.queried)
	}
}

// TestRecordRejectsNonCanonicalDirectoryKey pins the guard that keeps a
// malformed directory from crashing the gate: MemberIDFor hashes ANY byte
// slice, so an ID minted FROM a wrong-length key passes the binding check and
// would reach ed25519.Verify, which panics on non-canonical key lengths.
// Record must reject with ErrInvalid instead — for both parties.
func TestRecordRejectsNonCanonicalDirectoryKey(t *testing.T) {
	alice, alicePub, alicePriv := testMember(1)

	shortKey := ed25519.PublicKey([]byte{0xBE, 0xEF, 0xBE, 0xEF})
	shortID := MemberIDFor(testPlatform, shortKey) // minted from the short key: the binding check alone passes

	t.Run("assessor", func(t *testing.T) {
		dir := dirMap{shortID: shortKey, alice: alicePub}
		store := &countingStore{inner: NewMemStore()}
		b := testBook(t, dir, sealSet{}, store)

		a := testAssessment(shortID, alice, ref(0xAA), LevelBasicPromise)
		a.Sign(alicePriv) // content irrelevant: the guard fires before Verify (which would panic)
		err := b.Record(a)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("Record with a short assessor directory key = %v, want ErrInvalid (and no panic)", err)
		}
		if !strings.Contains(err.Error(), "non-canonical assessor key length") {
			t.Errorf("rejection reason = %q, want the assessor key-length guard", err)
		}
		if store.appends != 0 {
			t.Errorf("store saw %d appends, want 0", store.appends)
		}
	})

	t.Run("subject", func(t *testing.T) {
		dir := dirMap{alice: alicePub, shortID: shortKey}
		seals := sealSet{}
		seals.seal(ref(0xAA), alice, shortID) // sealed, so pre-guard the assessment would be ADMITTED
		store := &countingStore{inner: NewMemStore()}
		b := testBook(t, dir, seals, store)

		a := testAssessment(alice, shortID, ref(0xAA), LevelBasicPromise)
		a.Sign(alicePriv) // must genuinely verify: the assessor gates run before the subject guard
		err := b.Record(a)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("Record with a short subject directory key = %v, want ErrInvalid", err)
		}
		if !strings.Contains(err.Error(), "non-canonical subject key length") {
			t.Errorf("rejection reason = %q, want the subject key-length guard", err)
		}
		if store.appends != 0 {
			t.Errorf("store saw %d appends, want 0", store.appends)
		}
	})
}
