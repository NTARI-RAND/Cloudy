# lipu pi nasin sama — Janus-Facing Architecture (toki pona)

> **toki lili pi lipu ni:** lipu ni li lipu pi kulupu, li tan nasin NTARI "P2-002". lipu suli li lipu Inli "CONFORMANCE.md" (tenpo pi 2026-10-05). ilo sona li pali e lipu ni; kulupu li wile lukin e ona kepeken nasin "P2-002" kipisi "3.1".
>
> **Note:** This is a community rendering under NTARI policy P2-002. The complete document is the English original CONFORMANCE.md (snapshot 2026-10-05). Machine-assisted draft pending community review per P2-002 section 3.1.
>
> sina lukin e pakala lon toki ni la o pona e ona: o pali e "fork" lon
> https://github.com/NTARI-RAND/Cloudy, o pana e "pull request". pana sina
> li pona tawa mi mute.
>
> **lipu Inli li lawa.** lipu ni li tawa lukin, li tawa ala sona pi nasin lawa: lipu ni li ante tan `CONFORMANCE.md` la lipu Inli li lawa. nimi lawa (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY), nimi pi poki sona, nimi sitelen en nimi ilo li awen lon toki Inli, tan ni: ona li lipu lawa pi nasin sama.

---

lipu ni la poki lipu li toki e ona sama kepeken nimi pi nasin JFA. ona li toki e ni **lon open**, li toki e ijo pi ilo Cloudy taso lon monsi, tan nasin pi nanpa toki pi nasin JFA. toki ale pi nasin sama li linja tawa ilo en lukin ni: ilo en lukin li wawa e toki ni. linja li lon ala la sitelen li toki e ni: toki ni li ijo pi tenpo lili (stand-in) anu ijo open (stub). toki pi linja ala li toki esun taso.

nasin ni li **Janus-Facing Architecture (JFA)** — lipu wan pi nasin ilo pi kulupu NTARI. jan ale li ken kepeken lipu ni; ona li lon poki pi jan ale pi poki ni (nasin "AGPL-3.0").

## toki pi pali

ilo Cloudy li **lupa lukin** pi kipisi ilo JFA — ona li ilo tawa jan kulupu — li tomo pi **kipisi pi esun pi jan kulupu**. nasin insa pi kipisi ilo li toki ala e kipisi ni, tan wile: lipu toki pi jan pi ilo suli wan wan, toki awen pi sona pona jan, en mani pi jan kulupu (jan kulupu li pana e ona). jan kulupu li lon ni, li lon ni taso; linja pi nasin insa anpa poki ni li sona ala e jan. ilo Cloudy li ilo wan taso, li ken kama ilo sin tan sama ("fork"): ona li toki kepeken nasin insa open; ilo insa ale pi nasin sama li ken pana tawa ona.

| nimi pi poki ni | pali lon nasin JFA |
|---|---|
| `internal/record` | **lipu toki pi jan pi ilo suli wan wan** — toki sin taso li ken kama lon ona; toki li awen tan jan tu pi toki; jan lukin li lukin e ona |
| `internal/covenant` | ilo pi **nasin nanpa lukin** (sona pona pi jan kulupu li toki awen) |
| `internal/economy` | **mani pi jan kulupu** (jan kulupu li pana e ona) (esun pi jan kulupu) |
| `internal/coord` | ona li kepeken **nasin insa** pi kipisi ilo |
| `internal/enroll` | **lupa lukin li kama jan pi ilo suli** lon ilo insa (apply → keys → verify → conformance → active) |
| Member | jan, lon ilo wan taso; sona pi jan ("PII") li awen lon poki pi jan kulupu, jan li ken weka e ona |

## nasin awen en linja ona — lon `main`

toki pi lon seme li kama tan nasin pi toki lon pi nasin JFA. pali pini ante pi kipisi pi jan kulupu li lon kulupu PR open; ona li kama lon `main` la ona li ante e lipu leko ni.

| nasin awen (nasin JFA) | lon seme lon main | ilo / lukin |
|---|---|---|
| lipu awen li **kama suli taso**; pona pi pakala li toki sin | **Built** (pali li pini) | `internal/record`: Store/Log li pana e Append taso — nimi pali pi ante (update) en weka (delete) li lon ala; lipu pi poki ilo li toki e nasin pi sijelo ona; ilo lukin (tests) |
| lipu awen li **awen tan toki** — ona li ijo pi wile sama pi jan kulupu tu, li ijo pi toki pi jan wan ala | **Built** (pali li pini) | ilo li lukin e sitelen awen tu lon nanpa lili pi nasin wan (canonical bytes); jan li toki tawa ona sama la ilo li ken ala pali e toki ni |
| **sona pi jan ("PII") li lon ala poki pi jan ale**; toki suli li awen lon poki pi jan kulupu, jan li ken weka e ona | **Built** (pali li pini) | kule ijo pi poki pi jan ale li jo e nanpa "hash", e nimi open (keys), e tenpo taso; ijo pi ken weka li lon poki pi jan kulupu; kule ijo pi poki ni li wan ala tawa kule ijo pi poki pi jan ale |
| **jan lukin** li lon, li lawa ala tan jan ante tan sijelo pi nasin; ilo li jo e jan lukin wan taso la sitelen li toki e ni: ona li ijo pi tenpo lili | **Built (stand-in)** (pali li pini, li ijo pi tenpo lili) | jan lukin li sitelen e nimi ona lon poka; ilo li lukin e ni: jan lukin tu ale li lawa ala e jan ante; ilo li nanpa e sitelen StandIn; sitelen ni li kama ala tan toki jan taso |
| toki awen: **nanpa meso ala lon tenpo ale**; mute ale pi pana; jasima; ona li toki e ni taso: "esun li ken anu seme?", li toki ala e ni: "mute seme?" | **Stub, labeled** (ijo open, sitelen li toki e ni) | lipu pi poki ilo `internal/covenant` li toki e nasin awen; jan li ken ala ante e nasin ni; ilo pini o pona tawa nasin ni; ilo pini li lon lukin |
| esun: mani pi jan li **kama tan lipu awen taso, kepeken nasin pi ante ala**; nanpa ale li ala (0); mani awen li nanpa wan; jan li pali e mani, li esun ala e mani | **Stub, labeled** (ijo open, sitelen li toki e ni) | lipu pi poki ilo `internal/economy` li toki e nasin awen; ilo pini li lon lukin |
| **jan pali jo wan** — jan kulupu wan li jan pana li jan kama jo lon tenpo sama | Design-binding (nasin pi pali ilo li lawa) | nasin ilo ale (schema) en kule ijo ale li tu ala e jan pana e jan kama jo; lupa ale pi jan kulupu li kama la nasin ni li lawa e ona |
| **ken pi kama sin tan sama ("fork")** | Built (pali li pini) | ona li kepeken nasin insa lon nimi nanpa open (version tag); ilo insa ala li jo e ken suli |

## linja tawa lipu nimi pi nasin JFA

ilo lukin (tests) li linja e nimi nanpa (ID) tan lipu nimi pi nasin awen pi ilo Janus (`jfa-conformance-suite.py` lon NTARI-RAND/Janus) la nimi ona li `TestInvariant_<ID>_<Name>`. sitelen `-` li lon nimi nanpa la ona li kama `_` (sama ni: `REC-six-holders` li kama `TestInvariant_REC_six_holders_…`). `go test -run TestInvariant_ -v ./...` li pana e linja ale e pini ona.

| nimi nanpa (Registry ID) | ilo lukin (Test) | ona li pana e seme lon poka pi ilo lukin pi poki ilo |
|---|---|---|
| **L1** — esun ale li ante e mani tu; nanpa ale ona li ala | `internal/economy` `TestInvariant_L1_ZeroSumBalance` | jan pana mute li pana lon tenpo sama lon lipu mani tu; lipu tu li kepeken poki wan; nanpa pi toki wan wan li ala; ilo li pali sin e lipu la mani ale li kama sama |
| **L6** — ante lon poka sama ala, weka ala; jan li weka e toki la ona li pana e toki lon poka | `internal/record` `TestInvariant_L6_AppendOnly` (kipisi pi weka e toki: `internal/covenant` `TestAnswersCloseTheSymmetryBreach`) | pona pi pakala li toki sin lon pini; toki pakala en sitelen ale pi lon pi tenpo pini li awen sama; jan li sitelen sin e toki lon poki awen lon poka sama la ilo li lukin e ni: ona li sama ala sitelen awen (checkpoint) tan tenpo pini; ilo li lukin e lipu ilo ale pi kulupu ilo (module), li lukin ala e nimi pali pi ante (update) anu weka (delete) lon kule ijo ale pi kama suli taso — ilo li sona e kule ijo ni tan nimi (Store/Log/Ledger/Book) anu tan toki "append-only" lon lipu ilo; `market.Catalog` en `techtree.Tree` li awen lon lipu, la ona li ken ala weka tan lukin |
| **L7** — poki pi jan ale li jo e nanpa "hash", e kule ijo, e tenpo, e nasin tawa sona taso | `internal/record` `TestInvariant_L7_CommonsSchema` | kule ijo ale pi poki pi jan ale li ken jo e ni taso lon poki lili ale ona: kulupu nanpa lili (byte arrays), nanpa ale pi anpa ala (unsigned integers), `time.Time`, en poki lili `[]byte` lon lipu pi ken (allowlist) pi nimi open en sitelen nimi pi nasin ed25519 — sitelen toki (string) ala, poki nimi (map) ala, lupa ilo (interface) ala, nanpa kipisi (float) ala, `[]byte` pi lipu ala ala; jan li pana e toki lili (memo) tawa poki lili ale pi lipu pi ken la ilo lukin li pakala, taso ijo sama pi toki lili ala li pona; ijo ni li kama ala lon lipu awen (log) |
| **L8** — mute ale pi pana li awen; nanpa wan (scalar score) li lon ala lon ma ale | `internal/covenant` `TestInvariant_L8_NoScalarAggregation` | jan kulupu tu li jo e nanpa meso sama e selo ante la ilo li ken sona e ante ona; ilo li lukin e lipu ilo ale pi kulupu ilo (module) tawa ni: nasin pali open (exported functions) pi nimi "score" anu pi pana e nanpa kipisi (float), nimi lili JSON sama "score", en poki lili pi nanpa kipisi lon poki ilo pi sona pona jan |

## ijo pi tenpo lili en ijo pi pini ala

- **StandIn pi jan lukin wan.** tenpo ni la sitelen awen (checkpoint) ale pi jan lukin li jo e jan lukin ala anu jan lukin wan taso (jan lukin ni li lawa ala tan jan ante); kipisi pi lipu awen li nanpa e sitelen ni tan sijelo ona, li toki e ona. kulupu pi ilo mute (federation) pi tenpo lon li wile sona nanpa 2 pi pini ala pi nasin JFA — ona li pali pi kiwen lawa (keystone).
- **toki awen en esun li ijo open (stub) lon main.** lipu pi poki ilo ona li jo e nasin awen lawa; ilo pini li lon kulupu PR open (PR li lon sewi pi PR ante), li wile pona tawa lipu ni la ona li ken kama wan (merge).
- **ante nimi pi sitelen ma (domain tag) pi lipu awen** (nimi pi ilo esun) li pini ala, li wile kama **lon tenpo ni: awen suli li lon ala** — lipu awen suli li lon la nimi sin li sitelen sin pi lipu ale.
- **ijo pi pini ala lon lipu awen, li jo e nimi** (steganographic floor, timestamp covert channel, witness amnesia, liveness gap) li lon lipu pi poki ilo pi lipu awen; jan li len ala e ona, li toki ala e ni: "ona li lon ala."
- **ilo pana — selo Executor li pini; ilo pi tenpo pali li pini ala.** `internal/contribute` li awen e nasin lawa pi pana ilo (Executor / ServiceExecutor / Registry / NodeContract). nasin awen tu li lon, ilo lukin (tests) li wawa e ona: ilo pi tenpo lape (scavenged) li ken kepeken ilo pali ni taso: ilo ante li ken pini e ona (preemptible) (jan pi jo ilo li kama ala pini tan ni lon tenpo ale); pali Service li wile e ma awen (pinned placement). `cmd/cloudy-agent` li pali e ni tan open tawa pini kepeken ilo pali Storage **lon** (kipisi len pi sitelen awen + lukin pi jo `internal/storage`) en ilo pali Compute/Service **pi tenpo lili**. pali suli pi tawa ilo tan `internal/agent` pi ilo insa (ona li ijo pi tenpo ante) — ilo pali Docker, lukin pi ilo sijelo kepeken gopsutil, opt-out/allowlist/printers, en linja agent→cloudyd→`/v0` — li pali kama pi nimi, li kama *monsi* selo ni, li ante ala e selo.
- **ilo pi kama jan pi ilo suli — pali li pini, li lukin lon ilo lon.** `internal/enroll` + `cmd/cloudy-enroll` li tawa e nasin ale pi kama sin pi jan pi ilo suli lon ilo insa, tan open tawa pini (wile → sitelen e kulupu pi nimi open 7 → lukin kepeken lipu "email" → kulupu lukin A/B pi nasin sama → open pi ilo taso). ona li kepeken sin e `internal/opcred` tawa awen pi nimi open, li kepeken sin e ona tawa nanpa e toki pi nasin sama kepeken nasin lawa lon pi nasin insa. ilo insa li pana e nanpa pona tawa kulupu lukin C, la jan pi ilo suli li wile ala toki tawa ona; tan ni, tenpo pi kulupu lukin C li lon ala. ilo jan (client) li weka tan `internal/coord`, tan wile: kama sin li JSON taso lon selo **lupa** (portal) pi ilo insa, li lon ala linja `/v0` pi ilo anpa. nimi lili pi lipu "email" li kama tan nasin ante, kepeken `CodeSource` pi pana insa. ona li lukin lon ilo insa SoHoLINK lon — jan pi ilo suli sin li kama `active`, la sitelen ken ona li kama sona pona lon `/v0`.

## toki pi ijo wile

ona li kepeken `sohocloud-protocol` lon nimi nanpa open (version tag) — ona li kepeken ala ijo ante tan kulupu ilo. kipisi pi jan kulupu li toki e esun awen kepeken nimi nanpa len pi lipu lili (leaf ID), kepeken ijo ona (by value); ona li pana ala e kule ijo pi lipu awen tawa kipisi ante lon tenpo ale; ante li kama lon open pi wan ilo (composition root) taso.

## toki pi ilo Cloudy taso (lon pini, tan nasin pi nanpa toki)

ilo Cloudy li kama tawa jan kepeken ilo wan taso (ona li jo e API pi jan kulupu ona e selo ilo ona; ona li lon lukin). ilo SoHoLINK li ilo insa pi lipu sama, ilo Cloudy li toki tawa ona; ilo insa ale pi nasin sama li ken kama lon ma ona.
