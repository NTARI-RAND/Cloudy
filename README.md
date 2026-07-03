# Cloudy

A frontend on the SoHoLINK / sohocloud coordination network. Cloudy is where
members transact; it consumes substrate coordination through the shared
`sohocloud-protocol` module and owns its own JFA member economy on top.

## Status (honest)

This is a **skeleton**. One thing is real; the rest is deliberately stubbed.

- **Real:** `internal/coord` — a thin client over the protocol's reference
  HTTP+JSON transport, proving Cloudy consumes `sohocloud-protocol`.
  `cmd/cloudy` constructs it and reports startup; there is no live coordination
  loop yet.
- **Stub, not built:** the three JFA member-economy layers Cloudy owns and the
  protocol deliberately does not —
  - `internal/economy` — member-issued credit (spend-only, non-redeemable,
    non-purchasable, per-platform sovereign unit)
  - `internal/covenant` — reputation as a full distribution, never averaged
    (cross-platform portability is open problem #5, undecided)
  - `internal/record` — dialog-sealed, append-only, witnessed record, no PII in
    the commons

  Each names its non-negotiable invariants in its package doc.

## Import-graph invariant

Cloudy imports `sohocloud-protocol`; **nothing imports Cloudy**. Cloudy depends
on the protocol's core and its reference transport and reaches around neither.
The dependency direction is what keeps the frontend and the coordinator
separable: a frontend can be replaced without touching the substrate, and the
substrate does not know about any particular frontend.

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
