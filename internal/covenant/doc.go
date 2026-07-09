// Package covenant implements Cloudy's reputation covenant: how members come
// to trust one another on the platform, expressed as the full distribution of
// signed, exchange-anchored assessments on the Leveson-Based Trade Assessment
// Scale (LBTAS). This is a JFA member-economy layer that the substrate
// coordination protocol deliberately does not define, and it is Cloudy's to
// own.
//
// Reputation here is a read-derived shape, never a stored quantity and never
// a number. Each Assessment is one member's ed25519-signed verdict — one of
// the six LBTAS levels, under one category of a closed vocabulary — on how
// the counterparty honored the covenant of one sealed exchange, admitted
// through exactly one gate (Book.Record) and read back through exactly one
// query (Book.Standing).
//
// # The scale: LBTAS provenance
//
// The verdict vocabulary is NTARI's Leveson-Based Trade Assessment Scale, an
// adaptation of Nancy Leveson's aircraft-software assessment methodology —
// developed for a domain where a system failure means loss of life or wasted
// R&D, not a bruised ego — to digital commerce. The authoritative scale
// definitions and the reference implementations live in the
// Development/Covenant/Leveson-Based-Trade-Assessment-Scale repository
// (CLAUDE.md there is the binding spec; lbtas.py/.go/.rs/.ts are the
// reference read shapes). Six levels, displayed best to worst:
//
//	+4 Delight                  — anticipates the evolution of user practices and concerns post-transaction
//	+3 No Negative Consequences — designed to prevent loss; exceeds basic quality
//	+2 Basic Satisfaction       — meets socially acceptable standards beyond articulated demands
//	+1 Basic Promise            — meets all articulated demands, no more
//	 0 Cynical Satisfaction     — fulfills a basic promise with little to no discipline toward satisfaction
//	-1 No Trust                 — the counterparty was harmed, exploited, or served with no discipline or malicious intent
//
// The levels are meaning-loaded definitions, NOT points on a continuous
// axis: each carries a specific verdict, and adjacent levels are not "one
// unit apart" in any sense arithmetic could exploit. Level is an int8
// because the LBTAS wire and storage shapes are numeric (-1..+4) and the
// canonical signing bytes must encode a value a non-Go verifier can
// reproduce; arithmetic on Level has NO sanctioned use outside validation.
// The never-average rule therefore rests on the read surface — Distribution
// and Standing expose per-level counts and totals, nothing else — plus the
// two tripwire tests, exactly as the LBTAS reference implementations enforce
// it: their acceptance bar is that no average/mean logic exists in any read
// or report path.
//
// Assessment is BIDIRECTIONAL, and structurally so: both parties to a sealed
// exchange rate each other. Book.Record admits one verdict per (assessor,
// exchange, category), and either party of the sealed pair may be the
// assessor, so a single completed exchange grounds up to two verdicts per
// category — the producer's on the consumer and the consumer's on the
// producer. Nothing privileges either direction.
//
// # Invariants (NOT negotiable)
//
// Each invariant is enforced by making its violation inexpressible in this
// package's types, not merely forbidden in prose:
//
//   - Reputation is a full DISTRIBUTION, never a single averaged score. A
//     member's standing is the shape of all its assessments; it MUST NOT be
//     collapsed to one number, because averaging erases the shape that is
//     the actual signal — and it buries the safety signal: a No Trust (-1)
//     means someone was harmed, and a mean lets a single -1 be diluted by
//     surrounding praise. Harm is a discrete event to be surfaced, not
//     smoothed away; Standing.Harm raises the -1 count by name — a per-level
//     count, not a collapse. Enforced on the read surface: Book.Standing
//     returns a Standing whose entire method set is Category, Overall,
//     Total, and Harm, over Distributions whose entire method set is Count
//     and Total — over a finite ordinal domain the count-per-level histogram
//     IS the distribution, lossless — and no function anywhere returns a
//     scalar that summarizes assessment VALUES or defines any ordering or
//     comparison between members. Total is a scalar, but it is the
//     distribution's size, and per LBTAS the size is itself a signal: it
//     carries transaction volume and a proxy for time in service (a large
//     count generally cannot accumulate without sustained participation), so
//     a clean shape over 5,000 verdicts and the same shape over 5 are
//     different standings — exactly the magnitude a mean, dimensionless with
//     respect to count, would collapse. Distribution's and Standing's state
//     is unexported, so json.Marshal and every other generic serializer
//     yields nothing usable; fmt's %v and %+v verbs DO print the unexported
//     per-level counts maps, and that residual is named and accepted: the
//     histogram is exactly the data Count already exposes on purpose,
//     nothing more. A second named residual: any caller can loop Count over
//     Levels and average the counts outside this package. The package makes
//     collapse unexpressed, not unthinkable — the enforced line is that no
//     package vocabulary ever blesses a collapse. Two tripwire tests hold
//     that line: a reflection tripwire over the POINTER method sets (the
//     superset of value and pointer receivers) of Distribution, Standing,
//     Book, Admitted, MemStore, and Level fails the suite on any
//     collapse-named method (mean, avg, average, score, sum, median,
//     percentile, compare, rank, rating, grade, weight, scalar, numeric);
//     and because package-level collapse FUNCTIONS are invisible to
//     reflection — it only sees method sets — a companion go/ast scan over
//     the package source fails the suite on any exported function or method
//     declaration with a collapse-pattern name.
//
//   - Reputation is not currency. It MUST NOT be purchasable, transferable,
//     or redeemable. Enforced structurally: the only write path is
//     Book.Record, which requires a valid assessor signature (the key is
//     resolved through the injected Directory for the assessor named in the
//     message, so a caller cannot substitute a key) AND an Anchors
//     confirmation that the exchange is a sealed record entry between exactly
//     these two members — every verdict is priced at one real witnessed
//     exchange, and one verdict per (assessor, exchange, category) is
//     enforced atomically at the Store, so reputation cannot be farmed faster
//     than real exchanges occur. The Store port trades only in the
//     package-minted Admitted type, constructible solely inside this package,
//     so writing fabricated standing around the Book is a compile error, not
//     a code-review catch. No balance, grant, transfer, spend, or redeem API
//     exists, and there is no amendment or retraction: a supersession path
//     would be the purchase path ("change your assessment and I will…"), so
//     absence is the enforcement. Genuine reconciliation is a new sealed
//     exchange and a new assessment.
//
//   - Cross-platform reputation PORTABILITY is an open problem (#5) and is
//     deliberately undecided. This package MUST NOT bake in a portability
//     mechanism as a side effect of building single-platform reputation;
//     whether and how reputation crosses platform boundaries is a governance
//     decision this package refuses to preempt. Enforced structurally: no
//     type implements any encoding interface or defines Marshal, Unmarshal,
//     Export, Import, or Snapshot; Admitted, Distribution, and Standing have
//     unexported fields, so generic serializers emit nothing usable — the
//     durable-format decision is deferred to the same governance moment as
//     the portability decision, and MemStore is the only Store. Two honest
//     qualifications. First, an extracted signed Assessment IS
//     third-party-verifiable as bytes anywhere — ed25519 does not care where
//     it is checked — so ADMISSION, not verification, is the real gate: the
//     platform-scoped member IDs inside the signed bytes bind to one
//     platform's directory and sealed exchanges, and no foreign Book can
//     anchor them. Second, a "backup export" of the covenant record is not
//     inexpressible — it is one exported accessor away — the package REFUSES
//     to ship it; the tripwire tests and review culture are that fence, not
//     the type system.
//
// # The -1 comment requirement, reconciled with the no-PII commons
//
// LBTAS makes a justifying comment MANDATORY for a No Trust (-1) verdict —
// it is the only level that asserts harm or bad faith, so the most
// consequential rating must be accountable and reviewable — and bounds it at
// 500 words so it cannot become an unbounded dumping ground. The covenant
// commons, however, admits no free text: an append-only, unretractable
// record must not carry PII or narrative. The JFA reconciliation: the
// comment TEXT lives in erasable member-local storage — the record layer's
// Locker model — where it can be reviewed by authorized parties and erased
// by its owner; the 500-word bound is enforced at the API/composition
// boundary, the only place the text exists. The commons carries only
// Assessment.CommentHash, the signed SHA-256 of that comment: 32 opaque
// bytes that commit the assessor to a specific justification without
// admitting a single word of it into the record. Book.Record refuses a -1
// with a zero CommentHash and permits (zero or non-zero) the hash for levels
// 0..+4, where comments are optional.
//
// # Categories
//
// Every assessment names a category — the LBTAS defaults are reliability,
// usability, performance, and support — and the vocabulary is CLOSED: it is
// fixed at NewBook, and Record rejects any assessment whose Category is not
// a member, so the field is a selector over an operator-fixed set, never a
// free-text or PII channel. Uniqueness is per (assessor, exchange,
// category): one exchange grounds at most one verdict per category per
// assessor, forever.
//
// # Absences, and why each is load-bearing
//
// There is no score, no export, no amendment, no retraction, no free-text or
// metadata field (Category is a closed vocabulary and CommentHash is 32
// opaque bytes — neither can carry text), no recency decay, and no
// cross-member comparison. Each absence closes a specific attack: a metadata
// field is the PII conduit into an append-only, unretractable record; an
// export format is a portability mechanism waiting to be copied
// off-platform; a revision path is a purchase path; and decay is a
// reweighting — a partial collapse the distribution invariant does not
// license. Standing is the shape of ALL admitted assessments, undecayed and
// untimed; IssuedAt exists only inside the signed Assessment, so the
// standing query can never become a timestamped dossier.
//
// # The MemberID convention
//
// Human-chosen MemberIDs are FORBIDDEN. Every MemberID is minted by
// MemberIDFor — the lowercase-hex SHA-256 of platform-scoped canonical bytes
// over (platform, member public key) — and Book.Record rejects any assessor
// or subject that is not exactly 64 lowercase-hex characters. Two reasons.
// First, PII: a free-form member ID embedded twice in a signed, append-only,
// unretractable record is a PII smuggling channel — names and grievances
// would enter the record and never leave. Second, accidental portability:
// Assessor and Subject sit inside the signed canonical bytes, so
// platform-scoped IDs make the same real-world pair produce different signed
// bytes on every platform — the signature still verifies as bytes anywhere,
// but the IDs inside it are meaningless outside the minting platform, so the
// assessment cannot function as portable reputation evidence.
//
// The binding is also RE-VERIFIED, not assumed: a Book is constructed with
// its platform name, and Record re-derives MemberIDFor(platform, key) from
// the directory-resolved key of BOTH the assessor and the subject, rejecting
// any mismatch. Standing accrues to the ID string, so a dishonest directory
// that remapped an accrued MemberID onto a new key would otherwise let the
// new key holder inherit — or be framed by — the old identity's record.
//
// # The cross-layer reference
//
// An ExchangeRef carries exactly the record entry's leaf ID — the [32]byte
// identity of the fully sealed entry in internal/record — never a content
// hash, never a chain head, never a hex string. Conversion from the record
// layer's value happens only at the composition root (which also implements
// the Anchors predicate); covenant imports neither internal/record nor
// internal/economy and treats the reference as opaque bytes it never
// interprets.
//
// # Canonical bytes
//
// Assessment.CanonicalBytes fixes the signed field order: assessor, subject,
// exchange, category, level (canon Int64 of the LBTAS numeric value),
// commentHash, issuedAt — under the domain tag
// "cloudy/covenant/assessment/v0" (v0: unstable, layout may change).
package covenant
