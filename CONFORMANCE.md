# Conformance — Janus-Facing Architecture

The repo's self-description in the architecture's own terms, stated **before** anything product-specific, per the architecture's ordering rule. Every conformance claim is bound to the mechanism and check that enforces it, or it is labeled a stand-in or stub. Unbound prose is marketing.

The architecture is **Janus-Facing Architecture (JFA)** — NTARI's unified architecture document, free documentation under the project's AGPL-3.0 commons.

## Role declaration

Cloudy is a **front end** of a JFA substrate — the member-facing application — and the home of the **member-economy layers** the substrate coordination protocol deliberately does not define: the per-operator dialog record, the reputation covenant, and member-issued credit. Members exist here and only here; the coordination wire below this repo knows no persons. Cloudy is a standalone, forkable product: it speaks the published protocol and any conformant coordinator can serve it.

| This repo's term | Architecture role |
|---|---|
| `internal/record` | the **per-operator dialog ledger** — append-only, dialog-sealed, witnessed |
| `internal/covenant` | the **assessment scale** implementation (member reputation as covenant) |
| `internal/economy` | **member-issued credit** (the member economy) |
| `internal/coord` | consumption of the substrate **coordination protocol** |
| Member | a person, platform-scoped; PII stays member-local and erasable |

## Invariants and their bindings — as of `main`

Statuses are stated per the architecture's honesty rule. Built member-layer work beyond this exists in the open PR stack and updates this table as it lands.

| Invariant (architecture) | Status on main | Mechanism / check |
|---|---|---|
| Record is **append-only**; corrections are new entries | **Built** | `internal/record`: Store/Log expose Append only — update and delete are absent verbs; package doc states the structural rules; tests |
| Record is **dialog-sealed** — what two members agreed, not what one asserts | **Built** | Dual-seal verification over canonical bytes; self-dialog rejected at construction |
| **No PII in the commons**; narrative stays member-local and erasable | **Built** | Commons types carry hashes, keys, and instants only; erasable content lives in a type-disjoint member-local store |
| **Witnessing** with structural independence; a single-witness deployment is a labeled stand-in | **Built (stand-in)** | Witness countersignatures with pairwise-independence verification; the StandIn label is computed, not asserted |
| Covenant: **never average**; full distribution; symmetric; gates whether-never-how-much | **Stub, labeled** | `internal/covenant` package doc declares the non-negotiable invariants it must satisfy when built; built implementation in review |
| Economy: balances a **deterministic function of the sealed record**; zero-sum; escrow-first; earned-never-bought | **Stub, labeled** | `internal/economy` package doc declares the invariants; built implementation in review |
| **Single participant identity** — one member, simultaneously contributor and consumer | Design-binding | No producer/consumer split exists in any schema or type; binds every member surface as it lands |
| **Forkability** | Built | Consumes the coordination protocol at a published version tag; no coordinator is privileged |

## Stand-ins and open residuals

- **Single-witness StandIn.** Every witnessed checkpoint today has fewer than two independent witnesses; the record layer computes and reports this label structurally. Live federation is the architecture's open problem 2 — the keystone build.
- **Covenant and economy are stubs on main.** Their package docs carry the binding invariants; the built implementations are in the open, stacked PRs and must satisfy those docs to merge.
- **Record domain-tag rename** (product naming) is pending and must land **before any durable persistence** — retagging after durable logs exist would be a rewrite.
- **Named record residuals** (steganographic floor, timestamp covert channel, witness amnesia, liveness gap) are documented in the record package doc rather than pretended away.
- **Contributor node — Executor seam built; runtime implementations pending.** `internal/contribute` fixes the node-contribution contract (Executor / ServiceExecutor / Registry / NodeContract) with two invariants enforced by tests: a scavenged node accepts only preemptible executors (owner-never-interrupted), and a Service workload requires pinned placement. `cmd/cloudy-agent` runs it end to end with a **real** Storage executor (opaque sealed shards + the `internal/storage` proof-of-possession) and **placeholder** Compute/Service executors. The heavy runtime port from the coordinator's transitional `internal/agent` — Docker executor, gopsutil hardware sampling, opt-out/allowlist/printers, and the agent→cloudyd→`/v0` relay — is the named next step and lands *behind* this seam without changing it.

## Dependency declaration

Consumes `sohocloud-protocol` at a published version tag — nothing else from the stack. The member layers reference sealed exchanges by opaque leaf ID, by value, never by importing record types into other layers; conversion happens only at the composition root.

## Product-specific notes (last, per the ordering rule)

Cloudy ships as a standalone consumer product (its own member API and app surfaces, in review). SoHoLINK is the reference coordinator it speaks to; any conformant coordinator may replace it.
