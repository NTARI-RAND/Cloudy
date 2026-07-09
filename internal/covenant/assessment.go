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
const domainAssessment = "cloudy/covenant/assessment/v0"

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

// Assessment is one member's signed verdict on one sealed exchange it took
// part in, under one category of the Book's closed vocabulary. Its field set
// is closed — no free text, no note, no metadata map — so no PII or narrative
// conduit exists in the covenant record: Category is validated against a
// closed set at Record, and CommentHash is 32 opaque bytes, never text.
type Assessment struct {
	Assessor    MemberID    // who renders the verdict; must differ from Subject
	Subject     MemberID    // whose standing it shapes
	Exchange    ExchangeRef // sealed record entry this verdict is grounded in; zero is invalid
	Category    string      // one of the Book's closed category vocabulary; free text is rejected
	Level       Level       // one of the six LBTAS levels
	CommentHash [32]byte    // SHA-256 of the justifying comment; MUST be non-zero when Level is LevelNoTrust, MAY be zero otherwise
	IssuedAt    time.Time   // UTC; canonical encoding drops monotonic and location
	Signature   []byte      // ed25519 by the Assessor; excluded from CanonicalBytes
}

// CanonicalBytes returns the deterministic signing payload (canon encoder,
// domain tag "cloudy/covenant/assessment/v0") with Signature excluded; it is
// a signing payload only, never an export or interchange format. Field order
// is fixed and documented: assessor, subject, exchange, category, level
// (fixed 8-byte big-endian two's-complement Int64 of the LBTAS numeric
// value), commentHash, issuedAt.
func (a Assessment) CanonicalBytes() []byte {
	b := canon.New(domainAssessment)
	b.String(string(a.Assessor))
	b.String(string(a.Subject))
	b.Bytes(a.Exchange[:])
	b.String(a.Category)
	b.Int64(int64(a.Level))
	b.Bytes(a.CommentHash[:])
	b.Time(a.IssuedAt)
	return b.Sum()
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
