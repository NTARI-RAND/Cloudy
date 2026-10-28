# 0001 — A member's computer connects through its frontend

- **Status:** Accepted, 2026-10-27
- **Decided by:** Jodson Graves (President) and Calvin Secrest (Vice President), NTARI
- **Applies to:** `cmd/cloudy-agent`, cloudyd, and any coordinator Cloudy relays to
- **Revisit:** open to change like every decision (bylaws §2.3); Option B below stays available

## Context

A member's computer (a prosumer node) runs `cmd/cloudy-agent`. Since PR #26 the agent has a loop that lists the node, heartbeats, polls for work and reports, every call made by the node and every message signed with the node's own ed25519 key (SUB-no-inbound-requirement).

The loop needs a way to prove to the orchestrator that it may connect. SoHoLINK, the orchestrator, accepts two on its `/v0` surface: a node's own SPIFFE certificate, or an operator transmission from a frontend relaying its members' nodes.

The roles, since they are easy to swap:

| Role | Here | Does |
|---|---|---|
| Prosumer node | the member's computer, running `cloudy-agent` | contributes capacity |
| Frontend | Cloudy (cloudyd) | the member's platform: the market, the record, member data |
| Orchestrator | SoHoLINK | matches work across frontends and markets |

## Options

**A — through the frontend.** The node talks only to its frontend. The frontend vouches for it as operator and passes its signed messages to the orchestrator.

**B — direct.** The node holds a certificate issued by the orchestrator's certificate service (SPIRE, `spiffe://soholink.org/…`) and talks to the orchestrator itself.

In both, the node only calls out, and a frontend outside the Antare federation can run its own orchestrator (SPEC §5.4).

## Decision

**Option A.** Prosumers talk to their frontend. The orchestrator works one level up: it lets frontends trade with each other and never deals with prosumers or their personal information.

## Why

- **Traffic.** There are far more prosumers than frontends. With A, check-ins land at the frontend, which sends the orchestrator only what matching needs (who is available, and what they offer). The orchestrator's load grows with the number of frontends, not prosumers.
- **Privacy.** The frontend holds everything about its members. The orchestrator sees a machine ID, capacity and job results, and nothing that identifies a person ("persons never on the wire", sohocloud-protocol CLAUDE.md).
- **Integrity.** The frontend relays each node message unchanged. The node's signature lets the orchestrator confirm a report came from that machine and was not altered on the way; it identifies a machine, not a person.
- **Portability.** The node's identity is its own key, not a certificate from one orchestrator. A member moving to another frontend re-registers the same key; a frontend moving to another orchestrator changes nothing on members' machines. Members install nothing beyond the agent.

## Consequences

- **Next build:** the relay, agent → cloudyd → SoHoLINK `/v0`, with cloudyd authenticating as operator (`internal/coord.DialAsOperator`) and rolling heartbeats up before they reach the orchestrator.
- **Each frontend becomes the path for its own members.** A frontend outage stops its members' work, never other frontends'. Members can leave a frontend that serves them badly; the cost of leaving (bylaws §2.2) is what disciplines it.
- **The orchestrator must enroll node keys through the operator.** Node keys are public keys, not personal data.
- **Test to add:** a frontend outside Antare, running its own orchestrator, works end to end with the same agent.

## Not decided

- **Option B is not rejected.** It is how SoHoLINK's own agent connects today, and the loop works with either. A side-by-side comparison was deferred on 2026-10-27; build B when there is a reason to compare.
- **The roll-up rule** (how often the frontend reports availability upward, and what it sends) is set in the relay PR.
