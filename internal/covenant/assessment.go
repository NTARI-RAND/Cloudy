package covenant

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// domainAssessment tags the canonical signing payload of an Assessment. One
// tag per message, per canon's domain-separation rule: a covenant signature
// is not transferable to any other message type or platform tag. v0 is
// unstable — the byte layout may change without compatibility guarantees.
const domainAssessment = "cloudy/covenant/assessment/v1"

// domainAssessmentID tags the derivation of an assessment's identity — the
// hash other artifacts (answers) reference. Distinct from the signing tag:
// an ID is a hash role, never a signature role.
const domainAssessmentID = "cloudy/covenant/assessment-id/v1"

// domainAnswer tags the canonical signing payload of an Answer.
const domainAnswer = "cloudy/covenant/answer/v1"

// domainMember tags the hash derivation of a MemberID from a platform name
// and a member public key. Distinct from the assessment tag — a tag is never
// shared between a hash-derivation role and a signature role — and distinct
// from economy's account derivation, so covenant and economy IDs for the same
// key do not trivially equate.
const domainMember = "cloudy/covenant/member/v0"

// MemberID identifies a Cloudy member. Opaque and platform-local: not a key,
// not a DID, not a SPIFFE path — it binds to nothing outside Cloudy. Every
// MemberID is minted by MemberIDFor; human-chosen values are forbidden (see
// the package documentation for why), and Book.Record rejects any assessor or
// subject that is not exactly 64 lowercase-hex characters.
type MemberID string

// MemberIDFor mints the one canonical MemberID for a member: the
// lowercase-hex SHA-256 over canonical bytes, under a covenant-owned domain
// tag, of (platform, member public key). Because Assessor and Subject sit
// inside every assessment's signed bytes, platform scoping here makes
// assessments non-portable: the same real-world pair produces different
// signed bytes on every platform. This is the only mint — no other MemberID
// shape is admissible at Book.Record.
func MemberIDFor(platform string, pub ed25519.PublicKey) MemberID {
	b := canon.New(domainMember)
	b.String(platform)
	b.Bytes(pub)
	sum := sha256.Sum256(b.Sum())
	return MemberID(hex.EncodeToString(sum[:]))
}

// ExchangeRef is an opaque 32-byte reference to the sealed record entry of
// one exchange. It carries exactly the record entry's leaf ID, issued by the
// record layer and converted only at the composition root; covenant never
// interprets it, and the zero value is invalid.
type ExchangeRef [32]byte

// Level is one of the six levels of the Leveson-Based Trade Assessment Scale
// (LBTAS): a meaning-loaded verdict on how the subject honored the covenant
// of one exchange, NOT a point on a continuous axis. The numeric
// representation (-1..+4) exists because the LBTAS wire and storage shapes
// are numeric and the canonical signing bytes must be reproducible by non-Go
// verifiers; arithmetic on Level has no sanctioned use outside validation.
// Nothing in this package sums, averages, or otherwise collapses levels —
// see the package documentation and the tripwire tests that hold that line.
type Level int8

const (
	// LevelNoTrust (-1): the counterparty was harmed, exploited, or served
	// with no discipline or malicious intent. The only level that asserts
	// harm; Book.Record requires a non-zero CommentHash with it.
	LevelNoTrust Level = -1
	// LevelCynicalSatisfaction (0): fulfills a basic promise with little to
	// no discipline toward satisfaction.
	LevelCynicalSatisfaction Level = 0
	// LevelBasicPromise (+1): meets all articulated demands, no more.
	LevelBasicPromise Level = 1
	// LevelBasicSatisfaction (+2): meets socially acceptable standards beyond
	// articulated demands.
	LevelBasicSatisfaction Level = 2
	// LevelNoNegativeConsequences (+3): designed to prevent loss; exceeds
	// basic quality.
	LevelNoNegativeConsequences Level = 3
	// LevelDelight (+4): anticipates the evolution of user practices and
	// concerns post-transaction.
	LevelDelight Level = 4
)

// String returns the LBTAS label for the level.
func (l Level) String() string {
	switch l {
	case LevelNoTrust:
		return "No Trust"
	case LevelCynicalSatisfaction:
		return "Cynical Satisfaction"
	case LevelBasicPromise:
		return "Basic Promise"
	case LevelBasicSatisfaction:
		return "Basic Satisfaction"
	case LevelNoNegativeConsequences:
		return "No Negative Consequences"
	case LevelDelight:
		return "Delight"
	}
	return "invalid level " + strconv.Itoa(int(l))
}

// Levels returns the six LBTAS levels in display order — best to worst, +4
// down to -1 — per the LBTAS output contract for printed distributions. This
// is the only ordering this package defines over them; the array return value
// is a copy, so callers cannot mutate shared state.
func Levels() [6]Level {
	return [6]Level{
		LevelDelight,
		LevelNoNegativeConsequences,
		LevelBasicSatisfaction,
		LevelBasicPromise,
		LevelCynicalSatisfaction,
		LevelNoTrust,
	}
}

// validLevel reports whether l is exactly one of the six LBTAS levels. A
// deliberate switch over the named constants, not a range comparison:
// validation is the one sanctioned use of Level's numeric nature, and even
// here the levels are treated as an enumeration, not an interval.
func validLevel(l Level) bool {
	switch l {
	case LevelNoTrust, LevelCynicalSatisfaction, LevelBasicPromise,
		LevelBasicSatisfaction, LevelNoNegativeConsequences, LevelDelight:
		return true
	}
	return false
}

// Relation types a verdict by the relationship it rates. Trade,
// adjudication-conduct, and verdict-satisfaction are different relations
// with different base rates; the record MUST distinguish them, and no reader
// may collapse them into one figure — that is the average the covenant
// forbids, committed across relations instead of across ratings
// (architecture, Record invariants). The vocabulary is closed: a relation
// outside these three is rejected at Record.
type Relation string

const (
	// RelationTrade rates a counterparty's honoring of a sealed exchange —
	// the covenant's original and highest-volume relation.
	RelationTrade Relation = "trade"
	// RelationAdjudicationConduct rates how the adjudicating operator DID
	// ITS JOB on a claim the assessor was party to — responsiveness,
	// process, dwell. This is the governance-relevant stream: it is where
	// an operator can abuse the very users it also gates.
	RelationAdjudicationConduct Relation = "adjudication-conduct"
	// RelationVerdictSatisfaction rates a party's satisfaction with a
	// judgment. Unsuppressable, and therefore honest — but a No Trust here
	// is a losing party's displeasure, NOT operator misconduct; readers
	// must never conflate this stream with adjudication-conduct.
	RelationVerdictSatisfaction Relation = "verdict-satisfaction"
)

// validRelation reports whether r is one of the three covenant relations.
func validRelation(r Relation) bool {
	switch r {
	case RelationTrade, RelationAdjudicationConduct, RelationVerdictSatisfaction:
		return true
	}
	return false
}

// Relations returns the three relations in a stable display order.
func Relations() [3]Relation {
	return [3]Relation{RelationTrade, RelationAdjudicationConduct, RelationVerdictSatisfaction}
}

// Assessment is one member's signed verdict on one sealed exchange it took
// part in, under one category of the Book's closed vocabulary and one of the
// three typed relations. Its field set is closed — no free text, no note, no
// metadata map — so no PII or narrative conduit exists in the covenant
// record: Category and Relation are validated against closed sets at Record,
// and CommentHash is 32 opaque bytes, never text.
type Assessment struct {
	Assessor    MemberID    // who renders the verdict; must differ from Subject
	Subject     MemberID    // whose standing it shapes
	Exchange    ExchangeRef // sealed record entry this verdict is grounded in; zero is invalid
	Relation    Relation    // trade | adjudication-conduct | verdict-satisfaction; typed, never collapsed
	Category    string      // one of the Book's closed category vocabulary; free text is rejected
	Level       Level       // one of the six LBTAS levels
	CommentHash [32]byte    // SHA-256 of the justifying comment; MUST be non-zero when Level is LevelNoTrust, MAY be zero otherwise
	IssuedAt    time.Time   // UTC; canonical encoding drops monotonic and location
	Signature   []byte      // ed25519 by the Assessor; excluded from CanonicalBytes
}

// CanonicalBytes returns the deterministic signing payload (canon encoder,
// domain tag "cloudy/covenant/assessment/v1") with Signature excluded; it is
// a signing payload only, never an export or interchange format. Field order
// is fixed and documented: assessor, subject, exchange, relation, category,
// level (fixed 8-byte big-endian two's-complement Int64 of the LBTAS numeric
// value), commentHash, issuedAt. v1 adds relation inside the signed bytes —
// an assessor's signature binds the relation it rated, so a trade verdict
// can never be replayed as a conduct verdict.
func (a Assessment) CanonicalBytes() []byte {
	b := canon.New(domainAssessment)
	b.String(string(a.Assessor))
	b.String(string(a.Subject))
	b.Bytes(a.Exchange[:])
	b.String(string(a.Relation))
	b.String(a.Category)
	b.Int64(int64(a.Level))
	b.Bytes(a.CommentHash[:])
	b.Time(a.IssuedAt)
	return b.Sum()
}

// ID returns the assessment's identity: the SHA-256, under its own domain
// tag, of the canonical bytes plus the signature — the value an Answer
// references. Signature-inclusive, so an unsigned draft has no citable ID.
func (a Assessment) ID() [32]byte {
	b := canon.New(domainAssessmentID)
	b.Bytes(a.CanonicalBytes())
	b.Bytes(a.Signature)
	return sha256.Sum256(b.Sum())
}

// Sign sets Signature using the assessor's private key.
func (a *Assessment) Sign(priv ed25519.PrivateKey) {
	a.Signature = ed25519.Sign(priv, a.CanonicalBytes())
}

// Verify reports whether Signature is a valid assessor signature over the
// assessment (length-checked before verifying, per SPEC §3); pub is resolved
// out-of-band — covenant does not distribute keys.
func (a Assessment) Verify(pub ed25519.PublicKey) bool {
	return len(a.Signature) == ed25519.SignatureSize &&
		ed25519.Verify(pub, a.CanonicalBytes(), a.Signature)
}

// ErrInvalid is returned (wrapped, with the specific reason) when Record
// rejects an assessment: a member ID that is not a minted 64-lowercase-hex
// MemberID, self-assessment, zero ExchangeRef, a level outside the six LBTAS
// levels, a category outside the Book's closed vocabulary, a No Trust (-1)
// verdict without a justifying CommentHash, zero IssuedAt, unknown assessor
// or subject key, a directory key that does not mint the named member's ID on
// this platform, a signature that does not verify, or an exchange not sealed
// between these two members.
var ErrInvalid = errors.New("covenant: invalid assessment")

// ErrDuplicate is returned when an assessor has already assessed the same
// exchange under the same category; one exchange grounds at most one verdict
// per (assessor, category), forever.
var ErrDuplicate = errors.New("covenant: assessor already assessed this exchange under this category")

// Answer is the rated party's signed response to an assessment about them —
// the mechanism that keeps the covenant symmetric: every claim is
// answerable, an answer is an annotation that never erases or edits the
// assessment it answers, and the one place the architecture named the
// symmetry broken (an adjudicator rated without recourse) is closed by this
// artifact existing for every relation, adjudication-conduct included. Like
// the assessment, its field set is closed: the response text lives in
// erasable member-local storage; the commons carries only its digest.
type Answer struct {
	Assessment [32]byte  // Assessment.ID() of the verdict being answered
	Answerer   MemberID  // must be the assessment's Subject — only the rated party answers
	AnswerHash [32]byte  // SHA-256 of the member-local response text; non-zero
	IssuedAt   time.Time // UTC
	Signature  []byte    // ed25519 by the Answerer; excluded from CanonicalBytes
}

// CanonicalBytes returns the deterministic signing payload for the answer.
func (an Answer) CanonicalBytes() []byte {
	b := canon.New(domainAnswer)
	b.Bytes(an.Assessment[:])
	b.String(string(an.Answerer))
	b.Bytes(an.AnswerHash[:])
	b.Time(an.IssuedAt)
	return b.Sum()
}

// Sign sets Signature using the answerer's private key.
func (an *Answer) Sign(priv ed25519.PrivateKey) {
	an.Signature = ed25519.Sign(priv, an.CanonicalBytes())
}

// Verify reports whether Signature is a valid answerer signature.
func (an Answer) Verify(pub ed25519.PublicKey) bool {
	return len(an.Signature) == ed25519.SignatureSize &&
		ed25519.Verify(pub, an.CanonicalBytes(), an.Signature)
}

// ErrUnknownAssessment is returned when an answer references no admitted
// assessment in this Book's store.
var ErrUnknownAssessment = errors.New("covenant: answer references no admitted assessment")
