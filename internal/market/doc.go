// Package market is Cloudy's hardware marketplace: the JFA Economy & Education
// layer's "manufacturer & product listings" surface (Building JFA v2, Part III,
// surface #1) plus the "secondary markets" surface (#4). It composes the
// techtree (a product spec IS a techtree claim), the covenant (LBTAS ratings
// reflect on specific products), and a settlement rail — but, like every Cloudy
// JFA module, it imports ONLY the protocol canon and the standard library and
// holds cross-layer references as opaque [32]byte values. The composition root
// wires it to techtree/covenant/economy exactly as it wires the others; market
// never parses or resolves a ref.
//
// What it is. A maker lists a product in an allowed hardware category; the
// listing points at the product-spec CLAIM anchored in the techtree (SpecRef),
// so the specs a maker advertises are contestable claims, not marketing the
// operator vouches for — this is how "reputation cannot be advertised into
// existence" is structural. Buyers transact over a settlement rail and rate the
// exchange in the covenant; per-product LBTAS is the covenant's distribution
// grouped over a listing's recorded sales (SalesOf → covenant, joined at the
// root). Used goods trade on the same rails, carrying their prior sealed
// exchanges as witnessed provenance.
//
// Invariants (Building JFA v2, Part III + refuse-list):
//
//   - CATEGORY, NOT PAY-TO-LIST. A listing MUST declare an allowed hardware
//     category (aligned to the Substrate node-class taxonomy A/B/C/D); scope is
//     curated by TYPE, never by payment. There is deliberately NO promote /
//     sponsor / boost / rank field, and a tripwire test forbids one — paid
//     placement turns the market into an ad market (refuse-list).
//   - TWO RAILS, ONE WALL. A listing's AcceptedRails is a subset of
//     {fiat, member_credit}. Fiat and member credit never mix in a transaction
//     and are never convertible; the member-credit rail is only live once the
//     platform economy Mode is ModeCredit (Sybil + regulatory gated). Rail
//     enablement is per-market, layered on the one global switch — one
//     sovereign currency, per-market acceptance.
//   - SPECS ARE CLAIMS. A product's specs live as a techtree product_spec claim
//     (SpecRef); the market never asserts a spec as certified fact. No
//     "verified"/"official" flag exists here either (a tripwire forbids it) —
//     specs are contested and rated through the techtree + covenant, not
//     decreed true.
//   - NO PII IN THE COMMONS. A listing's field set is closed — no free text; the
//     product name, copy, and images live member-local (the Locker), the commons
//     carries only structural facts + the SpecRef. Per-platform, non-portable.
//   - APPEND-ONLY. The catalog is append-only and hash-chained, fully re-verified
//     on Open; a delisting is a new state annotation, never an erasure (record
//     invariant). Single-writer StandIn until the shared record witnessing
//     lands, labeled as one.
package market
