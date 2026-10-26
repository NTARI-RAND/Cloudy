# Downloading a signed claim

`GET /api/v1/claims/{id}/export` downloads `claim-{id}.json`. This is a public
structural read, like the existing claim summary. A malformed 32-byte hex ID
returns 400; an unknown ID returns 404. Error responses are not attachments.

The existing `GET /api/v1/claims/{id}` response is unchanged. It remains the
summary and local narrative view; the export is a separate closed structural
representation. The new handler reads a defensive claim copy under the store
lock and releases that lock before writing the response. It does not consult
the Locker, read private keys, append a record, or modify any artifact.

## File fields

| Field | Encoding and meaning |
| --- | --- |
| `claim_id` | Lowercase hex of the claim's 32-byte leaf ID; recompute it when verifying. |
| `platform` | The original signed platform binding; exporting does not move the claim to another platform. |
| `claimant` | Lowercase hex of the 32-byte Ed25519 public key. |
| `kind` | The existing signed `fact`, `technique`, or `product_spec` value. |
| `inputs_hash`, `method_hash`, `result_hash` | Lowercase hex of the three signed 32-byte narrative commitments. No narrative text is included. |
| `nonce` | Lowercase hex of the original signed 32-byte nonce. |
| `asserted_at_ns` | A **decimal JSON string** containing the exact signed Unix-nanosecond instant. Parse as a signed 64-bit integer or BigInt, never a floating-point Number. |
| `signature` | Lowercase hex of the 64-byte Ed25519 signature. |

The timestamp deliberately differs from the numeric `asserted_at_ns` in the
existing claim-ingestion request. Modern nanosecond timestamps exceed the
exact-integer range of JavaScript Numbers; using a string in this new download
format preserves every signed bit without altering the ingestion API.

## Offline verification

Decode hex with the widths above, parse the timestamp without rounding, and
reconstruct the claim. `internal/techtree.Claim.CanonicalBytes` defines the
signing payload: the existing `cloudy/techtree/claim/v0` domain, platform,
claimant, kind, three hashes, nonce, and instant, encoded with the published
protocol's `canon` encoding. Verify the Ed25519 signature under `claimant`.
Then recompute `Claim.ID()` using its separate ID domain and compare it with
both the file's `claim_id` and the requested ID. The JSON text itself is not the
signed byte representation; JSON field order and whitespace are immaterial.

`internal/consumerapi/claim_export_test.go` exercises registration, signed
ingestion, public download and independent reconstruction from the file bytes.
It verifies the signature and ID without using the server's export/ingestion
DTOs. Mutating any signed component, including one timestamp nanosecond or one
nonce byte, fails verification. The existing summary remains unchanged.

## What verification establishes

A successful signature check establishes that the artifact is unchanged and
signed by the included key. It does not identify a person, certify truth,
establish author reputation, prove inclusion in a witnessed log, or confer
authority. Independently establish which key/platform/claim ID you intended to
verify; a valid self-signed replacement file is not proof it is that claim.

The Technology Tree remains an unwitnessed single-writer stand-in as described
in `internal/techtree/doc.go`. This export adds no countersignature, witness
status assertion, server persistence, record-domain change, or coordination
wire extension. Narrative remains in the separate erasable member-local
store, and the existing copyright and AGPL terms apply.
