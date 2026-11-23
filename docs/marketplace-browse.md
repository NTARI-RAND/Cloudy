# Browsing hardware offers

`GET /api/v1/market/listings` is public and returns structural listing summaries
in catalogue append order. Browsing neither records an exchange nor authorizes
settlement. Maker keys are the existing platform member keys; the API adds no
producer/consumer identity split, paid placement, reputation score or ranking.

## Filters

| Parameter | Meaning |
| --- | --- |
| `category` | Existing hardware category: `computer`, `mobile_phone`, `tablet`, `smart_tv`, `tv_streaming_stick`, or `nas_storage`. Omitted/empty retains the existing behavior: no matches. |
| `maker` | Optional exact 32-byte Ed25519 public key, encoded as 64 hex characters. Uppercase and lowercase hex denote the same key. An unknown well-formed key returns an empty list. |
| `rail` | Optional `fiat` or `member_credit`. Repeat the parameter to match **any** selected rail. Omit it to impose no rail restriction. |

Category, maker and the rail selection combine with AND. For example:

```text
/api/v1/market/listings?category=computer&rail=fiat&rail=member_credit&limit=10
```

This returns computer offers accepting fiat, member credit, or both. Selecting
only `rail=member_credit` matches credit-only and dual-rail offers. These flags
describe the maker's signed acceptance, not the platform's current settlement
capabilities. Credit remains blocked while the economy is in escrow mode. Fiat
and credit remain separate, nonconvertible rails; no purchase or redemption of
member credit is added.

## Opt-in pagination

Supplying `limit` or `cursor` enables paged reads. `limit` must be 1–100; it
defaults to 50 when only `cursor` is supplied. Start at `cursor=0` or omit the
cursor on the first limited request.

An exhausted page can contain an empty array and has no continuation token:

```json
{"listings": []}
```

`listings` contains the same summary fields as before. When more matching
offers exist, `next_cursor` contains the running instance's log ID and a decimal
append position, separated by `:` (for example, `<64-hex-log-id>:125`). It points
after the last returned listing in the catalogue log. Follow it with the same category, maker, rail
selection and page limit. Treat it as a continuation token, not a result count:
sales and nonmatching listings also occupy log positions. Exhausted pages omit
`next_cursor`; `listings` is always an array, including for empty results.

Append positions stay stable as offers and sales are appended. Pagination is
live, not a frozen snapshot: later requests may include new offers and updated
sales counts. A cursor equal to the current log length returns an empty page;
a cursor beyond the current log length is invalid. Cursors are local to this
in-memory catalogue instance, not portable durable bookmarks. Tokens from another
instance or a previous run return HTTP 400, even when their position would fit
the current log. After a restart, start a fresh traversal with `cursor=0` or omit
the cursor on a limited request. Bare decimal continuations other than the
bootstrap value `0` are rejected. Changing filters also starts a fresh traversal.

Each request snapshots its summaries under the existing server lock and writes
the response after unlocking. Bounded reads allocate for the page, without
copying the complete log, full category results or sales histories. Sparse
filters may still scan all remaining log entries; this is not an indexed search
or a bound on scan CPU time. Legacy requests with neither pagination parameter
remain unbounded and preserve the `{"listings": [...]}` response shape.

## Invalid input and compatibility

Malformed URL query encoding, invalid nonempty categories, malformed/empty maker
keys, unknown/empty rails, and repeated singleton parameters (`category`,
`maker`, `limit`, `cursor`) return HTTP 400. Rails may repeat; duplicates do not
duplicate offers. Comma-separated rail values are not supported. Limits and cursor
positions must contain only ASCII decimal digits and fit a nonnegative Go `int`; signs,
whitespace, fractions, suffixes and overflow fail. Empty bounds fail rather than
silently becoming defaults. Unknown unrelated query parameters remain ignored.

Valid existing category-only requests retain their fields, append ordering and
empty-category behavior. Invalid categories now receive 400 rather than looking
like a successful empty result. No signed listing, domain tag, protocol message,
storage format, public-read authorization or governance policy changes.

## Verification

```sh
go test ./internal/consumerapi -run '^TestMarketplaceBrowse' -count=1
go test -race ./...
go vet ./...
go build ./...
go test ./internal/consumerapi -run '^$' -bench '^BenchmarkMarketplaceBrowse$' -benchmem
```

HTTP tests use real signed registration, product-spec claims, listing creation
and the catalogue. They check filter conjunction and rail OR semantics, dual-rail
offers, unknown keys, exact summary fields, sale-interleaved append cursors,
continuation after appends, rejection after a server restart, malformed instance
tokens, malformed requests, page limits and legacy behavior.
The benchmark uses a ten-offer page against 100 and 1,000 stored offers. It
measures local request allocations and time, not a production capacity guarantee.
