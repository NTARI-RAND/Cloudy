# Inspecting signed claim references

`GET /api/v1/claims/{id}/references` is public and additive. Existing claim summaries and reference creation are unchanged.

Query parameters:

- `direction` is required: `inbound` matches the reference's `to`; `outbound` matches its `from`.
- `kind` optionally filters `builds_on`, `cites`, `contests`, `reproduces`, or `refutes`.
- `limit` defaults to 50 and must be an integer from 1 through 100.
- `cursor` is an unsigned decimal append-log position. Omit it or use an empty string to start at zero. Positions count claims as well as references. A cursor beyond the current log is invalid.

Recognized query parameters must not be repeated. Invalid IDs, directions, kinds, limits, or cursors return HTTP 400; a well-formed ID for an unknown claim returns 404. Unknown query parameters are ignored.

The response is `{"references": [...], "next_cursor": "..."}`. An empty result uses `[]`; `next_cursor` is empty when this traversal has no more matching edges. Otherwise, pass it unchanged with the same claim, direction, and kind. Results follow accepted append order, with no ranking. Newly appended edges cannot shift existing cursor positions and may appear in subsequent pages; this is a live traversal, not a frozen snapshot. After exhaustion, start a new traversal to discover later appends.

Each reference contains `reference_id`, `platform`, `asserter`, `kind`, `from`, `to`, `nonce`, `asserted_at_ns`, and `signature`. Binary fields use hexadecimal. `asserted_at_ns` is a **decimal string**, preserving exact signed nanoseconds in JavaScript and other clients whose JSON numbers are floating point. Reconstruct a `techtree.Reference` with those signed fields to call `Verify()` and compare `ID()` with `reference_id`.

No claim narrative or Locker contents are exported. A signature establishes authorship and unchanged bytes, not truth, privileged status, or witness independence. The techtree remains its documented single-writer stand-in. Pages allocate copies for at most `limit` references; discovery scans append history without cloning the complete log. Sparse matches can still require a linear scan.
