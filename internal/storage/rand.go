package storage

import (
	cryptorand "crypto/rand"
	"io"
)

// Every randomness source in this package — object keys, GCM nonces, padding,
// placement shuffle, fetch jitter, challenge nonces, cover cadence — is taken
// as an io.Reader so tests can inject a deterministic stream. That seam is the
// security root of the layer, so it is anchored here rather than left to a
// caller that does not yet exist: a production caller passes nil and gets
// crypto/rand; ONLY tests pass a reader, and never a predictable one in
// anything that ships.
//
// randOr resolves that contract at every public entry point: nil means the
// cryptographically secure default, a non-nil reader is used verbatim.
func randOr(r io.Reader) io.Reader {
	if r == nil {
		return cryptorand.Reader
	}
	return r
}
