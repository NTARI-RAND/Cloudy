# Cloudy

> **toki pona:** lipu ni li lipu lili pi kulupu, tan nasin NTARI "P2-002". lipu
> ale li lipu "README.md" pi toki Inli (tenpo pi sitelen: 2026-07-29). ilo sona
> li pali e lipu ni, la kulupu o lukin o pona e ona, tan nasin "P2-002" kipisi
> nanpa 3.1.
>
> **English:** This is a condensed community rendering under NTARI policy
> P2-002. The complete document is the English original README.md (snapshot
> 2026-07-29). Machine-assisted draft pending community review per P2-002
> section 3.1.
>
> sina lukin e pakala lon toki ni la o pona e ona: o pali e "fork" lon
> https://github.com/NTARI-RAND/Cloudy, o pana e "pull request". pana sina li
> pona tawa mi mute.

## Cloudy li seme?

Cloudy li ilo sinpin pi kulupu ilo "SoHoLINK" / "sohocloud". jan kulupu li esun
lon ona. ona li kepeken nasin "sohocloud-protocol", li jo e mani nasin ona sama
("JFA member economy").

## kipisi tu wan — pini, li jo e ilo "tests"

- `internal/record` — sitelen awen pi esun. jan tu li pana e sitelen wawa, la
  esun li ken kama lon lipu. nimi jan li lon poki pi jan wan taso, li ken weka.
- `internal/economy` — mani. jan li pana e mani lon tenpo esun taso. nanpa pi
  mani ale li nanpa ala.
- `internal/covenant` — sona pi pona jan, tan nasin "LBTAS" pi NTARI: tan
  "-1 No Trust" tawa "+4 Delight". ilo li toki e nanpa mute, li **toki ala e
  nanpa meso**. jan li pana e "-1" la ona o pana e toki tan.
- `internal/coord` — ilo lili li toki tawa nasin "sohocloud-protocol".

## tenpo ni la seme?

pali kulupu pi tenpo ale li lon ala. lupa pi jan kulupu li lon ala kin. pali kama
li tu: ilo pi ilo sona jan (node agent), en lupa pi jan kulupu (member portal).
ona tu li lon poki "SoHoLINK" lon tenpo ni, taso ona li kama tawa Cloudy: ijo pi
jan li ijo pi ilo sinpin.

## nimi

jan kulupu (Member) li jan lon kulupu wan taso — jan sama li jan ante lon kulupu
ante. jan pali (Participant) li nasin pali: pana e ilo sona, pana e pali. ilo
sona (Node) li jo e nimi `/node/<id>`.

Cloudy li kepeken "sohocloud-protocol". ijo ala li kepeken Cloudy. tan ni la jan
li ken ante e ilo sinpin, li ken awen e insa.

## sina o pali e ona

o pana e poki "sohocloud-protocol" lon poki mama sama pi Cloudy. tenpo ni la jan
ante li ken ala pali e ona.

```
replace github.com/NTARI-RAND/sohocloud-protocol => ../sohocloud-protocol
```

```
go build ./...
go test ./...
```

## lipu lawa

AGPL-3.0-or-later.

*Network Theory Applied Research Institute, Inc. — 501(c)(3) — EIN 92-3047136 — info@ntari.org*
