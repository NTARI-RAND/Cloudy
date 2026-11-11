# 0002 — Pricing, fees, and member privacy

- **Status:** Accepted, 2026-11-03
- **Decided by:** Jodson Graves (President) and Calvin Secrest (Vice President), NTARI
- **Builds on:** [0001](0001-node-connects-through-its-frontend.md) (a member's computer connects through its frontend)
- **Applies to:** Cloudy (and every frontend), SoHoLINK (and every orchestrator), sohocloud-protocol's fee terms
- **Revisit:** open to change like every decision (bylaws §2.3)

## Context

Decision 0001 took persons out of the orchestrator: SoHoLINK talks only to frontends. That left open who pays whom for work done on a member's computer. Until now SoHoLINK took each job's payment, kept a platform share, and paid the computer's owner through Stripe — which needs SoHoLINK to know that owner.

## Decision

### Who pays whom

| Who | Pays | For |
|---|---|---|
| A prosumer | their own frontend | a coordination fee for transacting |
| The consuming prosumer | the producing prosumer | the work itself |
| Each frontend | the orchestrator | a transport fee, when a trade crosses two networks |

- **The consumer pays the producer through their platforms' own settlement**, never through the orchestrator:
  - **Escrow** where that is the standard of both networks: the consumer's payment is held by the operator and released to the producer.
  - **Mutual credit** only where both platforms allow it and are registered for it (L10: governance approval, membership notice, completed regulatory review): the producer earns community credit on their frontend's ledger, and each exchange moves two balances that net to zero (L1).
  - Escrowed money and community credit are never mixed (the economy-layer wall).
- **The orchestrator bills frontends only.** It holds no member money and pays no member. Its role is transport between networks.

### How work is priced

**Price = the producer's attested electricity rate × the computer's attested power draw while running × run time.**

Both inputs are stated by the producer. Nothing checks them, by design: a producer who overstates is rated down by the people they work for, and buyers can go elsewhere (the covenant, and the cost-of-leaving principle, bylaws §2.2). Adding enforcement on top would replace covenant self-regulation with control. A future change that verifies these numbers needs a new decision, not a quiet fix.

### Cross-network trades

A trade between two networks is two sovereign spends — one on each network's ledger, each in its own unit — bound together by the public chain so neither happens without the other. No currency crosses between networks (L3, REC-truth-not-currency). Cross-network trades therefore wait for the public chain, which is a Phase 2 build; trades within one network do not.

### Member privacy

- **Tor-style routing**, where even the frontend cannot see a member's address, is an **optional frontend customization**, not core code. Members' computers only call out, so it already works if a frontend offers it; no frontend is required to.
- **What we promise today:** *JFA software never stores members' IP addresses.* This is true of Cloudy and SoHoLINK now (they hold a connection's address only in memory, for the length of a request or a rate-limit window) and should be held true by a test.
- **What we do not promise yet:** that no one logs a member's address. Infrastructure in front of our software does: Cloudflare decrypts soholink.org traffic and sees visitors' addresses. The promise widens when that dependency is replaced with NTARI hardware and partnerships. Check the public wording with counsel before it is published.

## Consequences

- **SoHoLINK:** an operator registers its members' computers with no person attached — no participant, hostname, country, or payout account. SoHoLINK's Stripe payout to a computer's owner does not apply to operator-registered computers.
- **Cloudy:** settles its members' trades itself (escrow now; mutual credit through `internal/economy` once registered); collects its coordination fee from prosumers; pays SoHoLINK's transport fee for cross-network trades.
- **SoHoLINK's open question is answered:** its `CLAUDE.md` asks whether the coordinator settles with the member or with the frontend. Under this decision it settles only with the frontend, and only for the transport fee.
- **sohocloud-protocol:** today's fee terms (`fees.Terms`: a contributor share and a platform share of a job's price) describe the orchestrator splitting a payment. Under this decision the orchestrator charges a transport fee to frontends instead. Changing the terms is a wire change: SPEC first, then a version bump.

## Not decided

- The size of each fee, and what the transport fee is based on.
- The unit the transport fee is paid in between operators (dollars between organizations, outside the member economy, is the expected case).
- The test that holds the IP promise true.
