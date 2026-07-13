# Cloudy

A frontend on the SoHoLINK / sohocloud coordination network. Cloudy is where
members transact; it consumes substrate coordination through the shared
`sohocloud-protocol` module and owns its own JFA member economy on top.

## Status (honest)

The three JFA member-economy layers Cloudy owns — and the protocol
deliberately does not — are now **built, with tests**. There is still no live
coordination loop and no member-facing surface.

- **`internal/record` — built.** Dialog-sealed, append-only, witnessed record:
  each Entry carries both members' seals over canonical, domain-separated
  bytes, so a half-sealed or self-dealt covenant can never enter a log;
  per-operator hash-chained logs are fully re-verified on `OpenLog`; operator
  checkpoints plus independent witness countersignatures make any rewrite of
  checkpointed history cryptographically detectable (the CT factoring), and a
  single-witness deployment is labeled the stand-in it is. No PII shape exists
  in the commons — identifying content lives only in the erasable,
  member-local Locker. `Entry.ID()`, the leaf hash, is the one cross-layer
  exchange reference.
- **`internal/economy` — built.** Per-platform sovereign mutual credit:
  credit is issued at the moment of spending, within one uniform, governed
  debit cap, and the sum of all balances is always exactly zero. No mint,
  fiat field, redemption, or memo is representable; escrow-now/credit-later
  is exactly one quorum-signed PolicyChange on the same append-only store;
  `Open` fully replays and re-verifies every record. `Spend.ExchangeHash`
  carries the record entry's leaf ID but is deliberately opaque and unchecked
  at Post — anchoring is a composition-root concern.
- **`internal/covenant` — built.** Reputation on NTARI's Leveson-Based Trade
  Assessment Scale (LBTAS): six meaning-loaded levels from -1 No Trust to
  +4 Delight, bidirectional (both parties to a sealed exchange assess each
  other), rendered per category over a closed vocabulary (defaults:
  reliability, usability, performance, support), and read only as full
  count-per-level distributions — per-category, pooled overall, and a harm
  count that surfaces every -1 — **never averaged**, with no score, export,
  amendment, retraction, or cross-member comparison anywhere (two tripwire
  tests — a reflection method-set scan and a go/ast exported-function scan —
  keep it that way). A -1 verdict requires a justifying comment;
  the comment text lives in the erasable member-local Locker while only its
  hash rides in the commons. Every assessment is assessor-signed and priced
  at one sealed exchange through the Anchors gate; member IDs are
  platform-scoped key hashes, and human-chosen IDs are rejected outright.
  The binding spec and reference implementation live at
  `Development/Covenant/Leveson-Based-Trade-Assessment-Scale`.
- **Real but thin:** `internal/coord` — a thin client over the protocol's
  reference HTTP+JSON transport, proving Cloudy consumes `sohocloud-protocol`.
  `cmd/cloudy` constructs it and reports startup; there is no live coordination
  loop yet.

`cmd/cloudy` now constructs all three layers in memory at startup (ModeEscrow
genesis, empty operator log, empty covenant book over an empty shared member
directory) and logs one honest line per layer. Each package names its
non-negotiable invariants in its package doc.

## What Cloudy owns (architecture)

Under the resolved architecture, Cloudy — the frontend — owns the member's
whole world. Three capabilities, one owner:

- **The JFA member economy — built.** `internal/economy` (member-issued
  credit), `internal/covenant` (LBTAS reputation), `internal/record`
  (dialog-sealed record), exactly as documented above. These are Cloudy's and
  deliberately not the protocol's: persons never appear on the wire.
- **The node agent — Cloudy-owned, currently hosted in the coordinator repo
  pending migration.** Hardware detection, resource profiles,
  capability-listing generation, heartbeat, the job executor, local
  opt-out/allowlist enforcement, telemetry, and the member-machine installer.
  This code (`internal/agent`, `cmd/agent`, and the MSI installer) lives in
  the SoHoLINK repo today and keeps working there — a leftover of SoHoLINK's
  dual frontend+coordinator era, not SoHoLINK's long-term role. The agent is
  the member's presence on their own machine, so it belongs to the frontend;
  a coordinator that ships agents onto member hardware is a coordinator that
  touches member hardware, which SoHoLINK must never do.
- **The member portal — Cloudy-owned, currently hosted in the coordinator
  repo pending migration.** Register, login, dashboard, job submission, and
  opt-out. The surface formerly called the "participant portal"
  (`internal/portal`, `cmd/portal`, `web/` in the SoHoLINK repo) is
  henceforth Cloudy's member portal — member identity is a frontend concern,
  so the door members walk through must be the frontend's door.

The node agent and the member portal are the next build milestones now that
the three layers are library-complete. As the status above says honestly:
neither has an ingress here yet, and nothing in this repo pretends the
migration has already happened.

### Glossary

- **Member** — a person, always relative to a frontend/platform. Identity
  (platform-scoped MemberID), credit, LBTAS standing, sealed records, PII
  (erasable, member-local), and contributed machines are membership facts.
  Membership is covenant language — mutual obligation to a particular
  platform; the same human is a different member on every platform by
  cryptographic construction.
- **Participant** — a role, not an entity: a member acting in the
  coordinated economy, contributing nodes and/or submitting jobs — one
  unified identity, never split into producer and consumer.
  Coordinator-side person-records (SoHoLINK's participants table and portal
  accounts) are transitional surfaces from the dual era.
- **Node** — a machine a member contributes, identified by NodeID with the
  SPIFFE binding `/node/<id>` (the protocol's `identity/` package).

### Identity toward the coordinator

Two identities cross the frontend/coordinator boundary, and they must not be
conflated. Members' machines carry **workload identity**: a SPIFFE SVID under
`/node/<id>`, authorized coordinator-side exactly per the protocol SPEC —
machine identity, unchanged. Cloudy itself authenticates as an enrolled
**operator**: the frontend-as-operator model, a **design target** patterned
on Agrinet's Phase 5 operator scheme (an operators + operator-keys registry;
a rotating Ed25519 key set of seven, each transmission signed with two;
replay bounded by a timestamp window plus nonce cache — see
`Development/Economy/Agrinet backend/lib/operatorKeys.js` and
`backend/middleware/operatorAuth.js`). Rotation is the point: a static,
never-rotated shared key is precisely the anti-pattern the reference warns
against inheriting. Neither identity is ever a person: member identity stays
inside Cloudy.

## Import-graph invariant

Cloudy imports `sohocloud-protocol`; **nothing imports Cloudy**. Cloudy depends
on the protocol's core and its reference transport and reaches around neither.
The dependency direction is what keeps the frontend and the coordinator
separable: a frontend can be replaced without touching the substrate, and the
substrate does not know about any particular frontend.

Within Cloudy, the three JFA packages never import each other; each sees only
the standard library and the protocol's `canon` package, and all imports stay
one-directional. They meet only at the composition root: `test/composition`
is the one composition-root test — the single shared member directory, the
Anchors predicate joining covenant to record on `Entry.ID()`, and the full
member story live there — and `cmd/cloudy` performs the same composition at
startup.

## Building

The protocol module is currently private and untagged. This skeleton resolves it
via a `replace` directive to a **local sibling checkout**:

```
replace github.com/NTARI-RAND/sohocloud-protocol => ../sohocloud-protocol
```

So `sohocloud-protocol` must be cloned next to `Cloudy` (both under the same
parent directory). This `replace` is a local-development convenience — it is not
buildable by others as-is. Publishing Cloudy for external build will require
tagging the protocol module (or a `GOPRIVATE` + authenticated-fetch setup) and
dropping the `replace`.

```
go build ./...
go test ./...
```

## License

AGPL-3.0-or-later.

*Network Theory Applied Research Institute, Inc. — 501(c)(3) — EIN 92-3047136 — info@ntari.org*
