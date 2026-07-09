package economy

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// domainPolicy tags PolicyChange signatures (signature role); distinct from
// every other tag in this package.
const domainPolicy = "cloudy/economy/policy/v0"

// Mode is the platform's single escrow-now/credit-later policy switch.
type Mode string

const (
	// ModeEscrow: member credit is disabled; Post returns ErrCreditDisabled and
	// no credit-moving record is ever written — exchanges settle at the
	// coordinator-side fiat layer, which this package deliberately cannot
	// reference. Enact still records governed PolicyChanges, and Enact,
	// Policy, Balance, and Open behave identically to ModeCredit.
	ModeEscrow Mode = "escrow"
	// ModeCredit: Post admits payer-signed spends within Policy.DebitCap.
	ModeCredit Mode = "credit"
)

// validMode reports whether m is one of the enumerated modes.
func validMode(m Mode) bool {
	return m == ModeEscrow || m == ModeCredit
}

// Policy is the governed configuration. It deliberately has no per-account
// fields: the debit cap applies to every account identically, so no account —
// operator-held keys included — can be granted a deeper issuance well.
type Policy struct {
	Mode     Mode   // the one switch
	DebitCap Amount // uniform issuance limit: no balance may fall below -DebitCap
}

// validate rejects policies whose values would make admission arithmetic
// unsound. Called on the genesis policy at Open and on every PolicyChange.
func (p Policy) validate() error {
	if !validMode(p.Mode) {
		return fmt.Errorf("economy: unknown mode %q", p.Mode)
	}
	if uint64(p.DebitCap) > math.MaxInt64 {
		return errors.New("economy: debit cap exceeds int64 range")
	}
	return nil
}

// Genesis fixes the ledger's platform identity and governance at birth. It is
// out-of-band configuration, not a ledger record; Open validates it
// (non-empty Platform, 1 <= Threshold <= len(Stewards), known Mode) and it is
// immutable for the ledger's life — platform identity is deliberately NOT part
// of the mutable Policy, and the steward set does not rotate in v0.
type Genesis struct {
	Platform  string              // the sovereign unit's platform; bound into every record's canonical bytes
	Stewards  []ed25519.PublicKey // keys empowered to enact policy changes
	Threshold int                 // distinct steward signatures required to enact
	Policy    Policy              // initial policy (typically ModeEscrow)
}

// validate is Open's genesis check; failures are descriptive, non-sentinel
// configuration errors.
func (g Genesis) validate() error {
	if g.Platform == "" {
		return errors.New("economy: genesis platform must be non-empty")
	}
	if g.Threshold < 1 || g.Threshold > len(g.Stewards) {
		return fmt.Errorf("economy: genesis threshold %d must satisfy 1 <= threshold <= %d stewards",
			g.Threshold, len(g.Stewards))
	}
	if err := g.Policy.validate(); err != nil {
		return fmt.Errorf("economy: genesis policy invalid: %w", err)
	}
	return nil
}

// PolicyChange is the ONLY way policy moves after genesis: a quorum-signed,
// append-only ledger record. The escrow->credit flip is exactly one of these —
// one governed configuration change, itself auditable in the ledger's history.
type PolicyChange struct {
	Platform string    // must match the ledger's platform; inside CanonicalBytes
	Policy   Policy    // the complete new policy
	Version  uint64    // strictly monotonic; the ledger rejects rollback
	At       time.Time // UTC
	Sigs     [][]byte  // ed25519 steward signatures over CanonicalBytes; excluded from CanonicalBytes
}

// CanonicalBytes returns the signing payload with Sigs excluded, beginning
// with the domain tag "cloudy/economy/policy/v0" (field order: Platform,
// Policy.Mode, Policy.DebitCap as uint64, Version as uint64, At as time).
func (c PolicyChange) CanonicalBytes() []byte {
	b := canon.New(domainPolicy)
	b.String(c.Platform)
	b.String(string(c.Policy.Mode))
	b.Uint64(uint64(c.Policy.DebitCap))
	b.Uint64(c.Version)
	b.Time(c.At)
	return b.Sum()
}

// Sign appends one steward signature over CanonicalBytes.
func (c *PolicyChange) Sign(priv ed25519.PrivateKey) {
	c.Sigs = append(c.Sigs, ed25519.Sign(priv, c.CanonicalBytes()))
}

// Verify reports whether at least g.Threshold DISTINCT steward keys from g
// have valid signatures in Sigs; non-steward and duplicate signatures count
// nothing. Wrong-length signatures are rejected before ed25519 verification.
func (c PolicyChange) Verify(g Genesis) bool {
	if g.Threshold < 1 {
		return false
	}
	payload := c.CanonicalBytes()
	seen := make(map[string]bool, len(g.Stewards))
	distinct := 0
	for _, sig := range c.Sigs {
		if len(sig) != ed25519.SignatureSize {
			continue
		}
		for _, pub := range g.Stewards {
			if len(pub) != ed25519.PublicKeySize || seen[string(pub)] {
				continue
			}
			if ed25519.Verify(pub, payload, sig) {
				seen[string(pub)] = true
				distinct++
				break
			}
		}
	}
	return distinct >= g.Threshold
}

// record seals PolicyChange into the Record union.
func (PolicyChange) record() {}
