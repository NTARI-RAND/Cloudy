# CLAUDE.md — Cloudy

## What this repo is

The **front end** of a Janus-Facing Architecture substrate, and the home of the member-economy layers: the per-operator dialog record, the reputation covenant, and member-issued credit. Read `CONFORMANCE.md` first — it is the role declaration and the invariant-to-binding table, and it must be updated in the same PR as any change that alters a binding.

## Non-negotiable invariants

Not negotiable by feature request. Grouped by the layer they defend.

**Record (`internal/record`)**
- Append-only: no update, no delete, anywhere. Corrections are new entries.
- No PII in the commons: never add a `string` field, memo channel, or marshal/export path to a commons type (Entry, Checkpoint, Countersignature, Proof, WitnessedCheckpoint). Erasable content belongs to the member-local store only.
- Dialog-sealed: both members' seals over the same canonical bytes; no self-dialog.
- A witness confers no authority: witnessing is retrospective countersigning; any API that makes a witness signature a precondition for an operation is an invariant violation — stop and flag.
- StandIn honesty: any surface presenting witnessed data carries the computed stand-in label; never present one witness as federation.
- Domain tags are frozen once durable data exists. The pending product rename must land before durable persistence.

**Covenant (`internal/covenant`)**
- Never average ratings into a score — carry the full distribution, count at each level beside the total.
- The lowest rating is the breach itself. Volume never absolves harm.
- Symmetric: every claim answerable; dismissals are annotations, never erasures.
- Reputation gates **whether** a member transacts on trust, never **how much**. Non-portable by default.

**Economy (`internal/economy`)**
- Balances are a deterministic function of the sealed record; every sealed exchange moves two balances that net to zero.
- Issuance gated by the covenant, capped by a separate limit never derived from the harm distribution.
- Credit is earned, never bought; never redeemable for fiat. Denomination is not redemption. Escrow-first; the escrow-to-credit switch is governance, never a code default.

**Identity**
- Single participant identity: one member is simultaneously contributor and consumer. Never split into producer and consumer identities, in any schema, type, or UI.
- Persons never appear on the coordination wire; member identity stays platform-scoped, PII member-local and erasable.

## Change discipline

1. Branch → PR → CI green → human review. The author never merges their own PR. Claude drafts and proposes; a human disposes.
2. `CONFORMANCE.md` rides along: a change altering any binding updates it in the same PR.
3. A stub stays labeled a stub until its implementation satisfies its package doc's invariants; never quietly promote one.
4. Never force-push, rewrite published history, or move a published tag.

## Requests to refuse or flag

Stop, name the tension, and surface it — do not implement quietly: average ratings or show a single score; edit or delete a record entry; add PII or free-text to a commons type; let users buy or cash out credits; raise a credit limit from reputation; split producer/consumer identities; make witnessing a gate; present a single-witness deployment as federated.

## Tension protocol

If you notice yourself reframing an invariant so a feature becomes convenient, implementing a stand-in without labeling it, or routing around an open problem instead of noting it — stop. Name the tension, attach it to the invariant or open problem by name, and propose the minimal conformant move. Surface it; do not absorb it.
