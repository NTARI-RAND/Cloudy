# Janus Facing Architecture

The official document of the Janus Facing Architecture (JFA), stewarded by
Network Theory Applied Research Institute, Inc. (NTARI) under
[its bylaws](https://github.com/NTARI-RAND/bylaws) §1.4(a).

JFA lets communities address the economic reality of prosumership and offers a
path from exogenous, chartal money to endogenous mutual credit. It is organized
into five functional layers — Substrate, Record, Covenant, Governance, and
Economy & Information — each implemented in three tiers: frontend, orchestrator,
and protocol.

## The document

| | |
|---|---|
| **Official document** | [janus-facing-architecture.md](janus-facing-architecture.md) |
| **Unresolved questions** | [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md) |
| **Concepts carried from prior instruments** | [jfa-concept-triage-2026-08-24.md](jfa-concept-triage-2026-08-24.md) |
| **Executable conformance suite** | [jfa-conformance-suite.py](jfa-conformance-suite.py) |
| **Substrate under carrier constraints (P1-004, companion paper)** | [P1-004_Substrate-Constraints_v0.1.md](P1-004_Substrate-Constraints_v0.1.md) |
| **Prior instruments** | [Historical Docs/](Historical%20Docs/) |

The English document is authoritative. Translations are provided for reach, not
for interpretation.

| Language | File |
|---|---|
| العربية (Arabic) | [janus-facing-architecture.ar.md](janus-facing-architecture.ar.md) |
| Español (Spanish) | [janus-facing-architecture.es.md](janus-facing-architecture.es.md) |
| Français (French) | [janus-facing-architecture.fr.md](janus-facing-architecture.fr.md) |
| हिन्दी (Hindi) | [janus-facing-architecture.hi.md](janus-facing-architecture.hi.md) |
| Português (Portuguese) | [janus-facing-architecture.pt.md](janus-facing-architecture.pt.md) |
| toki pona | [janus-facing-architecture.tok.md](janus-facing-architecture.tok.md) |
| 中文 (Chinese) | [janus-facing-architecture.zh.md](janus-facing-architecture.zh.md) |

## The lines that cannot be crossed

The section of the official document titled *The Lines That Cannot Be Crossed*
carries the twelve provisions that no conforming implementation may violate.
Read it before building.

## Implementations

Reference implementations and instances live in their own repositories:

- [Tell](https://github.com/NTARI-RAND/Tell) — the Record layer: per-operator,
  witnessed, append-only record
- [Agrinet](https://github.com/NTARI-RAND/Agrinet) — federated agriculture
  network protocol
- [SoHoLINK](https://github.com/NTARI-RAND/SoHoLINK) ·
  [Cloudy](https://github.com/NTARI-RAND/Cloudy) ·
  [sohocloud-protocol](https://github.com/NTARI-RAND/sohocloud-protocol) —
  Substrate layer
- [lighthouse](https://github.com/NTARI-RAND/lighthouse) ·
  [shelter](https://github.com/NTARI-RAND/shelter) ·
  [childcare-trust-network](https://github.com/NTARI-RAND/childcare-trust-network) ·
  [shanina](https://github.com/NTARI-RAND/shanina) ·
  [COER](https://github.com/NTARI-RAND/COER) ·
  [world-chase-tag](https://github.com/NTARI-RAND/world-chase-tag) — Economy &
  Information layer seeds and instances

Seeds conform to the standard; the shape bends, the floors bind.

## Verifying the document

The suite is the load-bearing rung: it binds the prose to a registry of
invariants with stable IDs, so the document and the registry cannot drift apart
without the check failing. Standard library only, no dependencies.

```
python jfa-conformance-suite.py                 # check the document
python jfa-conformance-suite.py --list          # print the invariant registry
python jfa-conformance-suite.py --doc PATH      # check another copy
python jfa-conformance-suite.py --project PATH  # check a repo's open-questions deliverable
python jfa-conformance-suite.py --bindings ../Cloudy [../other-repo ...]
                                                # also report which delegated
                                                # invariants those repos bind
```

`--bindings` scans implementation repositories you have cloned beside this one
for test functions named `TestInvariant_<ID>_<Name>` (with any `-` in the ID
written `_`) and marks each implementation invariant they cite as **BOUND** —
the binding the bylaws define in P1-001 §9.14(b). It reports that a citing test
*exists*; whether it passes is that repository's own CI, so the suite never
reports a delegated invariant as passing (§9.15). A test citing an unregistered
ID fails the run.

Exit code 0 when every executed check passes, 1 otherwise. Run it after any
edit to the official document.

Of the 26 registered invariants, 3 are bound here at the document layer and 23
are **delegated** — they bind running software or a governance instrument, and
can only be enforced by tests living beside that code or that instrument. They
are carried in the registry with stable IDs and reported as delegated and
unbound until a repo ships tests citing those IDs. A conformant repo cites the
IDs; until it does, its conformance is self-attested. Reporting a delegated
invariant as "checked" from here would be self-attestation wearing a test
runner, so the stand-in is labeled instead.

## Not yet published here

The dispute-mechanics design — "the dispute-mechanics design" as
[the bylaws](https://github.com/NTARI-RAND/bylaws) §1.5 defines it — and the
structure and robotics articles are held in NTARI's document store and are not
in this repository yet.

## License

Two licenses, as the document's own footer states:

| What | License |
|---|---|
| The specification — the official document, its translations, and the prior instruments | [CC BY-SA 4.0](LICENSE-SPEC) |
| The software — the conformance suite | [AGPL-3.0](LICENSE) |
