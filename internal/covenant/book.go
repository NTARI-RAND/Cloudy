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

// Store is the persistence port. It is append-only by construction — no
// update, no delete — and trades only in Admitted. Implementations MUST
// reject a second value with the same (Assessor, Exchange, Category) with
// ErrDuplicate, atomically under concurrent Appends; MUST reject the zero
// Admitted (detectable by Assessment().Assessor == "") with ErrInvalid; and
// MUST return defensive copies from BySubject.
type Store interface {
	// Append durably records ad, or returns ErrDuplicate if an admitted
	// assessment already exists for (ad.Assessment().Assessor,
	// ad.Assessment().Exchange, ad.Assessment().Category).
	Append(ad Admitted) error
	// BySubject returns every admitted assessment whose Subject is subject,
	// in append order; an unknown subject yields an empty slice, not an error.
	BySubject(subject MemberID) ([]Admitted, error)
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
	if !b.anchors.Sealed(a.Exchange, a.Assessor, a.Subject) {
		return fmt.Errorf("%w: exchange is not sealed between these two members", ErrInvalid)
	}
	sig := make([]byte, len(a.Signature))
	copy(sig, a.Signature)
	a.Signature = sig
	return b.store.Append(Admitted{a: a})
}

// Standing returns subject's full standing in the LBTAS read shape: the
// lossless per-level count histogram of every admitted assessment about
// them, per category and pooled overall, with the No Trust count surfaced by
// Harm. A never-assessed member yields an empty Standing with Total zero,
// not an error. Nothing here — or anywhere in the package — returns a mean,
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
	s := Standing{
		byCategory: make(map[string]Distribution, len(b.categories)),
		overall:    Distribution{counts: make(map[Level]int, 6)},
	}
	seen := make(map[string]struct{}, len(ads))
	for _, ad := range ads {
		a := ad.Assessment()
		if a.Subject != subject {
			return Standing{}, fmt.Errorf(
				"covenant: Standing: store contract violation: BySubject(%q) returned an assessment about %q",
				subject, a.Subject)
		}
		key := string(a.Assessor) + "\x00" + string(a.Exchange[:]) + "\x00" + a.Category
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		d := s.byCategory[a.Category]
		if d.counts == nil {
			d.counts = make(map[Level]int, 6)
		}
		d.counts[a.Level]++
		d.total++
		s.byCategory[a.Category] = d
		s.overall.counts[a.Level]++
		s.overall.total++
	}
	return s, nil
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
