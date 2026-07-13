package covenant

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Directory resolves a member's ed25519 verification key. Resolution is
// platform-local and out-of-band; the covenant is not an identity registry
// and distributes no keys. The composition root backs it with the same member
// directory that answers for the economy and record layers, so one keypair
// speaks for a member everywhere.
type Directory interface {
	// PublicKey returns the member's verification key, or false if unknown.
	PublicKey(m MemberID) (ed25519.PublicKey, bool)
}

// Anchors reports whether an exchange reference names a sealed record entry
// binding exactly these two members. The composition root wires it to the
// record layer; covenant sees only opaque values, preserving the
// no-cross-layer-import rule.
type Anchors interface {
	// Sealed reports whether exchange is a sealed entry between assessor and subject.
	Sealed(exchange ExchangeRef, assessor, subject MemberID) bool
	// Adjudicated reports whether assessor was a genuine party to a claim on
	// this exchange that subject adjudicated (or is adjudicating) — the
	// anchor for the adjudication-conduct and verdict-satisfaction
	// relations. Grounding these on real claim participation is what keeps
	// the governance-relevant streams un-inflatable: a member who was never
	// party to a claim has no standing to rate its handling.
	Adjudicated(exchange ExchangeRef, assessor, subject MemberID) bool
}

// Admitted is an assessment the Book has verified and admitted. It cannot be
// constructed outside this package (unexported fields, no constructor), so a
// Store can hold admitted assessments but can never mint one — writing around
// the Book is a compile error.
type Admitted struct {
	a Assessment
}

// Assessment returns the admitted assessment. The Signature bytes are a
// fresh copy on every call, so no caller can mutate an admitted verdict.
func (ad Admitted) Assessment() Assessment {
	a := ad.a
	if a.Signature != nil {
		sig := make([]byte, len(a.Signature))
		copy(sig, a.Signature)
		a.Signature = sig
	}
	return a
}

// AdmittedAnswer is an answer the Book has verified and admitted; like
// Admitted it cannot be constructed outside this package, so a Store can
// hold answers but never mint one.
type AdmittedAnswer struct {
	an Answer
}

// Answer returns the admitted answer with a defensive signature copy.
func (aa AdmittedAnswer) Answer() Answer {
	an := aa.an
	if an.Signature != nil {
		sig := make([]byte, len(an.Signature))
		copy(sig, an.Signature)
		an.Signature = sig
	}
	return an
}

// Store is the persistence port. It is append-only by construction — no
// update, no delete — and trades only in Admitted and AdmittedAnswer.
// Implementations MUST reject a second assessment with the same (Assessor,
// Exchange, Relation, Category) with ErrDuplicate, atomically under
// concurrent Appends; MUST reject the zero Admitted (detectable by
// Assessment().Assessor == "") with ErrInvalid; MUST reject a second answer
// to the same assessment with ErrDuplicate (an answer annotates once; it is
// never edited); and MUST return defensive copies everywhere.
type Store interface {
	// Append durably records ad, or returns ErrDuplicate if an admitted
	// assessment already exists for (Assessor, Exchange, Relation, Category).
	Append(ad Admitted) error
	// BySubject returns every admitted assessment whose Subject is subject,
	// in append order; an unknown subject yields an empty slice, not an error.
	BySubject(subject MemberID) ([]Admitted, error)
	// ByID returns the admitted assessment with the given Assessment.ID(),
	// or ok=false when the store has never admitted it.
	ByID(id [32]byte) (Admitted, bool, error)
	// AppendAnswer durably records aa, or returns ErrDuplicate if the
	// referenced assessment already has an answer.
	AppendAnswer(aa AdmittedAnswer) error
	// AnswerFor returns the admitted answer for the assessment id, or
	// ok=false when it has none.
	AnswerFor(id [32]byte) (AdmittedAnswer, bool, error)
}

// lbtasDefaultCategories returns a fresh copy of the LBTAS default category
// vocabulary, used when NewBook is given no categories.
func lbtasDefaultCategories() []string {
	return []string{"reliability", "usability", "performance", "support"}
}

// Book is the only admission path into the covenant record and the only
// reader of standing; there is no operator write, no import, and no way to
// record an assessment that is not signed by its assessor and anchored to a
// sealed exchange. The Book knows its platform name so it can re-verify, on
// every admission, that the directory's key for each named member actually
// mints that member's ID — the directory is a dependency, not an authority.
// It also owns the closed category vocabulary every assessment must name a
// member of.
type Book struct {
	platform   string
	categories map[string]struct{}
	directory  Directory
	anchors    Anchors
	store      Store
}

// NewBook returns a Book enforcing covenant rules over the given member
// directory, anchor predicate, and store, for the named platform, with the
// given closed category vocabulary. A nil or empty categories slice defaults
// to the LBTAS four: reliability, usability, performance, support. An empty
// or duplicate category name is an error. Platform, directory, anchors, and
// store are required: an empty platform or a nil dependency is an error at
// construction, not a failure at first Record. The platform must be the same
// name the composition root passes to MemberIDFor when minting member IDs;
// Record uses it to re-derive and check the ID<->key binding.
func NewBook(platform string, categories []string, directory Directory, anchors Anchors, store Store) (*Book, error) {
	if platform == "" {
		return nil, errors.New("covenant: NewBook: empty platform")
	}
	if directory == nil {
		return nil, errors.New("covenant: NewBook: nil Directory")
	}
	if anchors == nil {
		return nil, errors.New("covenant: NewBook: nil Anchors")
	}
	if store == nil {
		return nil, errors.New("covenant: NewBook: nil Store")
	}
	if len(categories) == 0 {
		categories = lbtasDefaultCategories()
	}
	set := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		if c == "" {
			return nil, errors.New("covenant: NewBook: empty category name")
		}
		if _, dup := set[c]; dup {
			return nil, fmt.Errorf("covenant: NewBook: duplicate category %q", c)
		}
		set[c] = struct{}{}
	}
	return &Book{platform: platform, categories: set, directory: directory, anchors: anchors, store: store}, nil
}

// Record validates a, verifies its signature against the assessor's resolved
// key, re-verifies that the directory's keys for both assessor and subject
// actually mint those member IDs on this platform (so a dishonest directory
// cannot remap an accrued MemberID onto a new key and inherit its standing),
// confirms the exchange is sealed between exactly these two members, then
// mints an Admitted and appends it. It returns an error wrapping ErrInvalid
// or ErrDuplicate on rejection; nothing unverified reaches the Store, and an
// admitted verdict is final — no amendment, no retraction.
//
// LBTAS-specific gates: Level must be one of the six named levels (numeric
// values outside -1..+4, and unnamed values within the byte range, are
// rejected); Category must be a member of the Book's closed vocabulary; and a
// No Trust (-1) verdict must carry a non-zero CommentHash — the signed hash of
// the mandatory justifying comment, whose text lives in erasable member-local
// storage, never in the commons (see the package documentation).
func (b *Book) Record(a Assessment) error {
	if !validMemberID(a.Assessor) {
		return fmt.Errorf("%w: assessor is not a minted member ID (must be exactly 64 lowercase-hex characters)", ErrInvalid)
	}
	if !validMemberID(a.Subject) {
		return fmt.Errorf("%w: subject is not a minted member ID (must be exactly 64 lowercase-hex characters)", ErrInvalid)
	}
	if a.Assessor == a.Subject {
		return fmt.Errorf("%w: self-assessment", ErrInvalid)
	}
	if a.Exchange == (ExchangeRef{}) {
		return fmt.Errorf("%w: zero exchange reference", ErrInvalid)
	}
	if !validRelation(a.Relation) {
		return fmt.Errorf("%w: relation %q is not one of the covenant's three typed relations", ErrInvalid, string(a.Relation))
	}
	if !validLevel(a.Level) {
		return fmt.Errorf("%w: level %d is not one of the six LBTAS levels (-1..+4)", ErrInvalid, int8(a.Level))
	}
	if _, ok := b.categories[a.Category]; !ok {
		return fmt.Errorf("%w: category %q is not in this Book's closed vocabulary", ErrInvalid, a.Category)
	}
	if a.Level == LevelNoTrust && a.CommentHash == ([32]byte{}) {
		return fmt.Errorf("%w: a No Trust (-1) verdict requires a non-zero CommentHash over its justifying comment", ErrInvalid)
	}
	if a.IssuedAt.IsZero() {
		return fmt.Errorf("%w: zero IssuedAt", ErrInvalid)
	}
	pub, ok := b.directory.PublicKey(a.Assessor)
	if !ok {
		return fmt.Errorf("%w: unknown assessor key", ErrInvalid)
	}
	// Length-guard before Verify: ed25519.Verify panics on a non-canonical key
	// length, and MemberIDFor hashes any byte slice, so a directory entry whose
	// ID was minted FROM a malformed key would pass the binding check below and
	// reach the panic. Reject, never crash, on a malformed directory.
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: directory returned a non-canonical assessor key length", ErrInvalid)
	}
	if MemberIDFor(b.platform, pub) != a.Assessor {
		return fmt.Errorf("%w: directory key does not mint the assessor's member ID", ErrInvalid)
	}
	if !a.Verify(pub) {
		return fmt.Errorf("%w: signature does not verify", ErrInvalid)
	}
	subjectPub, ok := b.directory.PublicKey(a.Subject)
	if !ok {
		return fmt.Errorf("%w: unknown subject key", ErrInvalid)
	}
	if len(subjectPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: directory returned a non-canonical subject key length", ErrInvalid)
	}
	if MemberIDFor(b.platform, subjectPub) != a.Subject {
		return fmt.Errorf("%w: directory key does not mint the subject's member ID", ErrInvalid)
	}
	switch a.Relation {
	case RelationTrade:
		if !b.anchors.Sealed(a.Exchange, a.Assessor, a.Subject) {
			return fmt.Errorf("%w: exchange is not sealed between these two members", ErrInvalid)
		}
	default:
		// adjudication-conduct and verdict-satisfaction anchor on real claim
		// participation: the assessor was a party to a claim on this
		// exchange, and the subject is its adjudicator.
		if !b.anchors.Adjudicated(a.Exchange, a.Assessor, a.Subject) {
			return fmt.Errorf("%w: no adjudicated claim on this exchange binds this assessor to this adjudicator", ErrInvalid)
		}
	}
	sig := make([]byte, len(a.Signature))
	copy(sig, a.Signature)
	a.Signature = sig
	return b.store.Append(Admitted{a: a})
}

// Standing returns subject's full standing in the LBTAS read shape, TYPED
// BY RELATION: for each of the three relations, the lossless per-level count
// histogram per category and pooled within that relation, with the No Trust
// count surfaced by Harm. There is deliberately no cross-relation pool: an
// operator's verdict-satisfaction ratings never blur into its
// adjudication-conduct stream, and neither blurs into trade. A
// never-assessed member yields an empty Standing, not an error. Nothing here — or anywhere in the package — returns a mean,
// average, or scalar summary of level values.
//
// Standing does not trust the Store's indexing — the signed data is the
// authority, because a Store that misroutes or replays admitted verdicts
// could otherwise re-attribute standing (a currency-shaped breach). It
// re-validates every returned Admitted: an assessment whose Subject is not
// the queried subject is a Store contract violation and returns an error, and
// replays of the same (Assessor, Exchange, Category) verdict are counted
// exactly once.
func (b *Book) Standing(subject MemberID) (Standing, error) {
	// A subject that is not a minted member ID can have no standing; querying
	// one (e.g. "") must not let a hostile Store attach phantom entries to it.
	if !validMemberID(subject) {
		return Standing{}, fmt.Errorf("%w: subject is not a minted member ID (must be exactly 64 lowercase-hex characters)", ErrInvalid)
	}
	ads, err := b.store.BySubject(subject)
	if err != nil {
		return Standing{}, err
	}
	s := Standing{perRelation: make(map[Relation]RelationStanding, 3)}
	seen := make(map[string]struct{}, len(ads))
	for _, ad := range ads {
		a := ad.Assessment()
		if a.Subject != subject {
			return Standing{}, fmt.Errorf(
				"covenant: Standing: store contract violation: BySubject(%q) returned an assessment about %q",
				subject, a.Subject)
		}
		key := string(a.Assessor) + "\x00" + string(a.Exchange[:]) + "\x00" + string(a.Relation) + "\x00" + a.Category
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		rs, ok := s.perRelation[a.Relation]
		if !ok {
			rs = RelationStanding{
				byCategory: make(map[string]Distribution, len(b.categories)),
				overall:    Distribution{counts: make(map[Level]int, 6)},
			}
		}
		d := rs.byCategory[a.Category]
		if d.counts == nil {
			d.counts = make(map[Level]int, 6)
		}
		d.counts[a.Level]++
		d.total++
		rs.byCategory[a.Category] = d
		rs.overall.counts[a.Level]++
		rs.overall.total++
		s.perRelation[a.Relation] = rs
	}
	return s, nil
}

// RecordAnswer validates an answer, verifies it references an admitted
// assessment, that the answerer IS that assessment's Subject (only the
// rated party answers), verifies the key binding and signature exactly as
// Record does for assessments, and appends it. The answered assessment is
// untouched: an answer annotates, never edits — a dismissal is a new
// visible annotation, never an erasure.
func (b *Book) RecordAnswer(an Answer) error {
	if an.Assessment == ([32]byte{}) {
		return fmt.Errorf("%w: answer references no assessment", ErrInvalid)
	}
	if !validMemberID(an.Answerer) {
		return fmt.Errorf("%w: answerer is not a minted member ID (must be exactly 64 lowercase-hex characters)", ErrInvalid)
	}
	if an.AnswerHash == ([32]byte{}) {
		return fmt.Errorf("%w: an answer requires a non-zero AnswerHash over its member-local response", ErrInvalid)
	}
	if an.IssuedAt.IsZero() {
		return fmt.Errorf("%w: zero IssuedAt", ErrInvalid)
	}
	ad, ok, err := b.store.ByID(an.Assessment)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUnknownAssessment
	}
	subject := ad.Assessment().Subject
	if an.Answerer != subject {
		return fmt.Errorf("%w: only the rated party may answer (answerer is not the assessment's subject)", ErrInvalid)
	}
	pub, ok := b.directory.PublicKey(an.Answerer)
	if !ok {
		return fmt.Errorf("%w: unknown answerer key", ErrInvalid)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: directory returned a non-canonical answerer key length", ErrInvalid)
	}
	if MemberIDFor(b.platform, pub) != an.Answerer {
		return fmt.Errorf("%w: directory key does not mint the answerer's member ID", ErrInvalid)
	}
	if !an.Verify(pub) {
		return fmt.Errorf("%w: signature does not verify", ErrInvalid)
	}
	sig := make([]byte, len(an.Signature))
	copy(sig, an.Signature)
	an.Signature = sig
	return b.store.AppendAnswer(AdmittedAnswer{an: an})
}

// AnswerFor returns the admitted answer to the assessment id, if any.
func (b *Book) AnswerFor(id [32]byte) (Answer, bool, error) {
	aa, ok, err := b.store.AnswerFor(id)
	if err != nil || !ok {
		return Answer{}, ok, err
	}
	return aa.Answer(), true, nil
}

// validMemberID reports whether m has the one admissible shape: exactly 64
// lowercase-hex characters, the output shape of MemberIDFor. Anything else —
// in particular any human-chosen name — is rejected at the gate.
func validMemberID(m MemberID) bool {
	if len(m) != 64 {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
