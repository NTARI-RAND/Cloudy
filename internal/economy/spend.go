package economy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Domain tags. One distinct tag per message or derivation, never a bare
// package tag, and never shared between a hash-derivation role and a
// signature role — so an account-ID preimage can never double as a signing
// payload and a signature over one record kind can never be replayed as
// another.
const (
	domainAcct  = "cloudy/economy/acct/v0"  // AccountID derivation (hash role)
	domainSpend = "cloudy/economy/spend/v0" // Spend signatures (signature role)
)

// Amount is a quantity of Cloudy's own sovereign unit; unsigned, so a negative
// transfer is unrepresentable. Zero is rejected at Post; values above
// math.MaxInt64 are rejected so Balance arithmetic cannot overflow.
type Amount uint64

// Balance is an account's signed net position; negative means the member has
// issued that much credit into circulation. The sum over all accounts is
// always exactly zero.
type Balance int64

// AccountID is the platform-scoped member identifier: a hash of the member's
// public key bound to the platform ID, so it carries no PII and the same key
// yields a different, non-correlatable ID on any other platform.
type AccountID [32]byte

// AccountIDFor derives the account ID: SHA-256 over the canon bytes of
// (domain tag "cloudy/economy/acct/v0", platform, public key).
func AccountIDFor(platform string, pub ed25519.PublicKey) AccountID {
	b := canon.New(domainAcct)
	b.String(platform)
	b.Bytes(pub)
	return AccountID(sha256.Sum256(b.Sum()))
}

// Spend is the only credit-moving record: a payer-signed transfer that creates
// credit at the moment of spending by driving From negative within the debit
// cap. It has no memo, no metadata, no currency, and no fiat reference — only
// an opaque hash committing to the sealed dialog in internal/record.
type Spend struct {
	Platform     string    // platform this spend is bound to; inside CanonicalBytes, so foreign spends never verify
	From         AccountID // the payer: the member issuing credit by going negative; signs the spend
	To           AccountID // the payee receiving the claim; must differ from From and resolve in the Directory
	Amount       Amount    // strictly positive
	ExchangeHash [32]byte  // the record entry's leaf ID: an opaque cross-layer commitment, never parsed here
	IssuedAt     time.Time // UTC instant; canon drops location and monotonic components
	Nonce        uint64    // strictly monotonic per From account; the ledger rejects replay and rollback
	Signature    []byte    // ed25519 by the payer; excluded from CanonicalBytes
}

// CanonicalBytes returns the deterministic signing payload with Signature
// excluded, beginning with the domain tag "cloudy/economy/spend/v0" (field
// order: Platform, From, To, Amount as uint64, ExchangeHash as bytes, IssuedAt
// as time, Nonce as uint64).
func (s Spend) CanonicalBytes() []byte {
	b := canon.New(domainSpend)
	b.String(s.Platform)
	b.Bytes(s.From[:])
	b.Bytes(s.To[:])
	b.Uint64(uint64(s.Amount))
	b.Bytes(s.ExchangeHash[:])
	b.Time(s.IssuedAt)
	b.Uint64(s.Nonce)
	return b.Sum()
}

// Sign sets Signature using the payer's private key.
func (s *Spend) Sign(priv ed25519.PrivateKey) {
	s.Signature = ed25519.Sign(priv, s.CanonicalBytes())
}

// Verify reports whether Signature is a valid payer signature over the spend;
// it rejects signatures whose length is not ed25519.SignatureSize before
// verifying. pub is the payer's public key, resolved out-of-band via the
// Directory; this package does not distribute keys.
func (s Spend) Verify(pub ed25519.PublicKey) bool {
	return len(s.Signature) == ed25519.SignatureSize &&
		ed25519.Verify(pub, s.CanonicalBytes(), s.Signature)
}

// record seals Spend into the Record union.
func (Spend) record() {}
