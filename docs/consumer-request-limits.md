# Consumer API request limits

The member-facing JSON write routes enforce a complete encoded-body byte limit
before JSON decoding, signature checks or store mutation. An oversized body
receives HTTP 413 with a JSON error. This applies with `Content-Length` and with
chunked or otherwise unknown-length bodies, including excess whitespace after a
valid signed object. The boundary is inclusive: a body exactly at the limit
continues to the existing validation and signature checks.

| POST routes | Default encoded bytes | Daemon flag |
| --- | ---: | --- |
| `/api/v1/claims` | 1,048,576 (1 MiB) | `-claim-request-bytes` |
| `/api/v1/members`, `/api/v1/references`, `/api/v1/market/listings`, `/api/v1/drops`, `/api/v1/credit/spends`, `/api/v1/assessments`, `/api/v1/assessments/{id}/answers`, `/api/v1/disputes`, `/api/v1/disputes/{id}/withdraw` | 65,536 (64 KiB) | `-request-bytes` |

Structural requests consist of keys, hashes, signatures, timestamps and labels.
The existing signed request fixtures fit well below the structural budget. Claims
also transport three arbitrary member-local narrative strings, so their default
budget is larger. Neither class has an existing domain-wide maximum: these are
adjustable frontend deployment budgets, not consensus rules, new enrollment
conditions, fees or limits on the canonical signed artifacts.

For a deployment that needs a larger narrative envelope:

```sh
go run ./cmd/cloudyd -request-bytes 65536 -claim-request-bytes 2097152
```

Both settings must be positive; zero or a negative value fails daemon startup.
Callers embedding the API may pass `consumerapi.RequestLimits` to
`consumerapi.NewServerWithLimits`. Existing `NewServer` callers use
`consumerapi.DefaultRequestLimits` without a source change. Configure a server
before exposing its handler; the settings are immutable during requests.

The count includes the whole encoded JSON envelope, escapes, ignored fields and
trailing bytes, not merely decoded narrative lengths. HTTP chunk framing is not
part of the body count. No request decompression is added. The guard reads at
most the configured limit plus one byte to detect an unknown-length overflow;
a declared oversized body is rejected without an application read. The original
body is closed on success, overflow and read failure. A body read or close failure returns
HTTP 400 without dispatching the write handler.

Accepted bytes are replayed unchanged to the existing decoder. Existing JSON
field handling and signature verification remain intact; this change adds no
end-of-document rule for an in-bounds body. Signatures, public structural reads,
member-local narrative separation and the escrow policy keep their existing
meaning. These controls apply only to the ten consumer JSON write routes, not
node relay `/v0/` traffic, unrelated witness daemons or response sizes.

Memory use is bounded per request, not across simultaneous requests. HTTP timeouts,
request concurrency limits and reverse-proxy policies remain separate deployment
concerns. Stores and operator keys retain their existing in-memory/ephemeral
limitations; request bounds do not make this a durable deployment.

Verification lives in `internal/consumerapi/request_limits_test.go`,
`internal/consumerapi/request_limits_boundary_test.go`,
`internal/consumerapi/request_limits_http_test.go`,
`internal/consumerapi/request_limits_io_test.go` and
`cmd/cloudyd/request_limits_test.go`. Tests cover every mounted JSON write route,
known/unknown lengths, real chunked HTTP, exact boundaries, signed registration
and narrative claims, unchanged stores on rejection, read bounds and body cleanup.
