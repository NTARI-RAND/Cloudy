package covenant

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// adjSet is a test Anchors with BOTH anchor kinds configurable.
type adjSet struct {
	seals sealSet
	adj   map[string]struct{}
}

func newAdjSet() *adjSet {
	return &adjSet{seals: sealSet{}, adj: map[string]struct{}{}}
}

func (a *adjSet) adjudicate(ex ExchangeRef, assessor, subject MemberID) {
	a.adj[string(ex[:])+"\x00"+string(assessor)+"\x00"+string(subject)] = struct{}{}
}

func (a *adjSet) Sealed(ex ExchangeRef, assessor, subject MemberID) bool {
	return a.seals.Sealed(ex, assessor, subject)
}

func (a *adjSet) Adjudicated(ex ExchangeRef, assessor, subject MemberID) bool {
	_, ok := a.adj[string(ex[:])+"\x00"+string(assessor)+"\x00"+string(subject)]
	return ok
}

// TestRelationsAreTypedAndGated: the relation vocabulary is closed; trade
// anchors on the sealed exchange; the adjudication relations anchor on real
// claim participation; and the same exchange supports one verdict per
// relation per category without colliding.
func TestRelationsAreTypedAndGated(t *testing.T) {
	member, pub, priv := testMember(1)
	operator, opPub, _ := testMember(2)
	dir := dirMap{member: pub, operator: opPub}
	anchors := newAdjSet()
	store := NewMemStore()
	b, err := NewBook(testPlatform, nil, dir, anchors, store)
	if err != nil {
		t.Fatalf("NewBook: %v", err)
	}
	ex := ref(0x11)
	anchors.seals.seal(ex, member, operator)

	base := func(rel Relation) Assessment {
		a := Assessment{
			Assessor: member,
			Subject:  operator,
			Exchange: ex,
			Relation: rel,
			Category: testCategory,
			Level:    LevelBasicPromise,
			IssuedAt: time.Unix(1700000000, 0).UTC(),
		}
		return a
	}

	// Closed vocabulary.
	bad := base("vibes")
	bad.Sign(priv)
	if err := b.Record(bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown relation admitted: %v", err)
	}
	empty := base("")
	empty.Sign(priv)
	if err := b.Record(empty); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty relation admitted: %v", err)
	}

	// Trade anchors on the seal (present) — admitted.
	trade := base(RelationTrade)
	trade.Sign(priv)
	if err := b.Record(trade); err != nil {
		t.Fatalf("trade: %v", err)
	}

	// Conduct WITHOUT an adjudicated claim is refused…
	conduct := base(RelationAdjudicationConduct)
	conduct.Sign(priv)
	if err := b.Record(conduct); !errors.Is(err, ErrInvalid) {
		t.Fatalf("conduct without claim admitted: %v", err)
	}
	// …and admitted once the member was party to a real claim.
	anchors.adjudicate(ex, member, operator)
	conduct = base(RelationAdjudicationConduct)
	conduct.Sign(priv)
	if err := b.Record(conduct); err != nil {
		t.Fatalf("conduct with claim: %v", err)
	}
	// Verdict-satisfaction rides the same anchor.
	vs := base(RelationVerdictSatisfaction)
	vs.Level = LevelNoTrust // a losing party's displeasure…
	vs.CommentHash = commentHash(0xAB)
	vs.Sign(priv)
	if err := b.Record(vs); err != nil {
		t.Fatalf("verdict-satisfaction: %v", err)
	}

	// One verdict per (assessor, exchange, RELATION, category): the trade
	// verdict did not block the conduct verdict, but a trade replay is dup.
	dup := base(RelationTrade)
	dup.Level = LevelDelight
	dup.Sign(priv)
	if err := b.Record(dup); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same-relation replay: %v", err)
	}

	// Standing keeps the streams apart — the verdict-satisfaction No Trust
	// does NOT appear in adjudication-conduct or trade, and there is no
	// cross-relation pool anywhere on the type.
	s, err := b.Standing(operator)
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if s.Relation(RelationTrade).Harm() != 0 || s.Relation(RelationAdjudicationConduct).Harm() != 0 {
		t.Fatal("a verdict-satisfaction No Trust leaked into another relation's harm count")
	}
	if s.Relation(RelationVerdictSatisfaction).Harm() != 1 {
		t.Fatal("the verdict-satisfaction No Trust must be visible in its own stream")
	}
	if s.Relation(RelationTrade).Total() != 1 || s.Relation(RelationAdjudicationConduct).Total() != 1 || s.Relation(RelationVerdictSatisfaction).Total() != 1 {
		t.Fatalf("per-relation totals = %d/%d/%d, want 1/1/1",
			s.Relation(RelationTrade).Total(), s.Relation(RelationAdjudicationConduct).Total(), s.Relation(RelationVerdictSatisfaction).Total())
	}
}

// TestAnswersCloseTheSymmetryBreach: every claim is answerable — the rated
// party (adjudicator included) answers with a signed annotation; the
// assessment is never altered; only the subject may answer; one answer per
// assessment; an answer to nothing is refused.
func TestAnswersCloseTheSymmetryBreach(t *testing.T) {
	member, pub, priv := testMember(1)
	operator, opPub, opPriv := testMember(2)
	dir := dirMap{member: pub, operator: opPub}
	anchors := newAdjSet()
	store := NewMemStore()
	b, err := NewBook(testPlatform, nil, dir, anchors, store)
	if err != nil {
		t.Fatalf("NewBook: %v", err)
	}
	ex := ref(0x22)
	anchors.adjudicate(ex, member, operator)

	// The member rates the OPERATOR's adjudication conduct No Trust — the
	// exact configuration the architecture named as the broken symmetry.
	a := Assessment{
		Assessor:    member,
		Subject:     operator,
		Exchange:    ex,
		Relation:    RelationAdjudicationConduct,
		Category:    testCategory,
		Level:       LevelNoTrust,
		CommentHash: commentHash(0xCD),
		IssuedAt:    time.Unix(1700000000, 0).UTC(),
	}
	a.Sign(priv)
	if err := b.Record(a); err != nil {
		t.Fatalf("Record: %v", err)
	}

	answerHash := sha256.Sum256([]byte("member-local response narrative"))
	an := Answer{
		Assessment: a.ID(),
		Answerer:   operator,
		AnswerHash: answerHash,
		IssuedAt:   time.Unix(1700000100, 0).UTC(),
	}

	// Only the rated party answers: the assessor's own signature is refused.
	wrong := an
	wrong.Answerer = member
	wrong.Sign(priv)
	if err := b.RecordAnswer(wrong); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-subject answer admitted: %v", err)
	}

	// The adjudicator answers — the recourse exists.
	an.Sign(opPriv)
	if err := b.RecordAnswer(an); err != nil {
		t.Fatalf("RecordAnswer: %v", err)
	}
	got, ok, err := b.AnswerFor(a.ID())
	if err != nil || !ok {
		t.Fatalf("AnswerFor: ok=%v err=%v", ok, err)
	}
	if got.Answerer != operator || got.AnswerHash != answerHash {
		t.Fatal("stored answer does not match")
	}

	// The answer annotates; the assessment's standing is untouched.
	s, err := b.Standing(operator)
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if s.Relation(RelationAdjudicationConduct).Harm() != 1 {
		t.Fatal("an answer must never dilute or erase the harm it answers")
	}

	// One answer per assessment, forever.
	again := an
	again.IssuedAt = an.IssuedAt.Add(time.Hour)
	again.Sign(opPriv)
	if err := b.RecordAnswer(again); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second answer admitted: %v", err)
	}

	// Answering a nonexistent assessment is refused with the named error.
	ghost := Answer{Assessment: [32]byte{9}, Answerer: operator, AnswerHash: answerHash, IssuedAt: an.IssuedAt}
	ghost.Sign(opPriv)
	if err := b.RecordAnswer(ghost); !errors.Is(err, ErrUnknownAssessment) {
		t.Fatalf("ghost answer: %v", err)
	}

	// A tampered answer signature is refused.
	tampered := Answer{Assessment: a.ID(), Answerer: operator, AnswerHash: commentHash(0xEE), IssuedAt: an.IssuedAt}
	tampered.Sign(opPriv)
	tampered.AnswerHash = commentHash(0xEF)
	if err := b.RecordAnswer(tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered answer admitted: %v", err)
	}
}
