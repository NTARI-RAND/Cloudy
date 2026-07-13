package opcred

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// delegationDomain tags the canonical bytes a root delegation is signed over.
const delegationDomain = "cloudy/opcred/delegation/v0"

// MaxDelegationTTL is the longest window IssueDelegation will sign.
// "Short-lived" is machine-enforced, not a convention; changing it is a
// deliberate design change, not a config tweak.
const MaxDelegationTTL = 30 * 24 * time.Hour

// Errors returned by the delegation paths. Distinguishable so a caller can
// tell an expired delegation from a forged or mismatched one.
var (
	ErrDelegationBadSignature   = errors.New("opcred: delegation signature does not verify against the pinned root key")
	ErrDelegationKeysetMismatch = errors.New("opcred: delegation was issued for a different keyset")
	ErrDelegationNotYetValid    = errors.New("opcred: delegation is not yet valid")
	ErrDelegationExpired        = errors.New("opcred: delegation has expired")
	ErrDelegationWindow         = errors.New("opcred: delegation window is empty or inverted")
	ErrDelegationTTL            = errors.New("opcred: delegation window exceeds MaxDelegationTTL")
)

// RootSigner is the root-of-trust seam. The root key signs ONLY delegations
// over an online keyset hash; it never signs live traffic.
//
// StandIn is explicit labeling: true means the root private key is
// software-held on local disk, standing in for a device. A deployment MUST
// surface a stand-in root to its operator. The intended future slot is a
// DeviceRootSigner backed by an HSM or security key: it implements this same
// interface with StandIn() == false, keeps the private key non-exportable in
// hardware, and requires NO changes to Delegation, IssueDelegation, or
// VerifyDelegation. No stub type is shipped until that implementation exists.
//
// Delegation ENFORCEMENT — refusing to sign transmissions without a live
// delegation — is a deliberate composition-root follow-up. This file provides
// the verify helper and custody structure only.
type RootSigner interface {
	// PublicKey returns the root public key.
	PublicKey() ed25519.PublicKey
	// Sign returns the root's signature over msg (canonical bytes; the caller
	// never asks a RootSigner to construct message bytes).
	Sign(msg []byte) ([]byte, error)
	// StandIn reports whether this root is a software stand-in for a device.
	StandIn() bool
}

// Delegation is a root-signed statement that a specific online keyset (by
// hash) is authorized within a time window. NotBefore and NotAfter are raw
// int64 UTC Unix-nanoseconds, deliberately NOT time.Time: the values verified
// are the exact signed int64s, with no time.Time round-trip between issue and
// verify. Both bounds are INCLUSIVE. RootPub is carried alongside for
// transport convenience; verification pins the caller-supplied root key, never
// the carried one. Sig is excluded from the canonical bytes.
type Delegation struct {
	KeysetHash [32]byte
	NotBefore  int64 // raw UnixNano, inclusive
	NotAfter   int64 // raw UnixNano, inclusive
	RootPub    []byte
	Sig        []byte
}

// CanonicalBytes returns the deterministic signing payload with the signature
// (and the merely-carried RootPub) excluded.
func (d Delegation) CanonicalBytes() []byte {
	b := canon.New(delegationDomain)
	b.Bytes(d.KeysetHash[:])
	b.Int64(d.NotBefore)
	b.Int64(d.NotAfter)
	return b.Sum()
}

// IssueDelegation signs a delegation over the keyset's hash for the window
// [notBefore, notAfter]. It rejects an empty or inverted window and a window
// longer than MaxDelegationTTL.
func IssueDelegation(rs RootSigner, ks *Keyset, notBefore, notAfter time.Time) (Delegation, error) {
	nb := notBefore.UTC().UnixNano()
	na := notAfter.UTC().UnixNano()
	if na <= nb {
		return Delegation{}, ErrDelegationWindow
	}
	if na-nb > int64(MaxDelegationTTL) {
		return Delegation{}, ErrDelegationTTL
	}
	d := Delegation{
		KeysetHash: ks.Hash(),
		NotBefore:  nb,
		NotAfter:   na,
	}
	sig, err := rs.Sign(d.CanonicalBytes())
	if err != nil {
		return Delegation{}, err
	}
	d.Sig = sig
	d.RootPub = append([]byte(nil), rs.PublicKey()...)
	return d, nil
}

// VerifyDelegation checks d against the caller-pinned root public key — NOT
// the carried d.RootPub, so a swapped-in carried key can never self-authorize
// — and against the expected keyset hash, at the given instant. Checks run in
// order: signature, keyset binding, validity window. The window bounds are
// inclusive: at == NotBefore and at == NotAfter are both valid.
func VerifyDelegation(d Delegation, rootPub ed25519.PublicKey, keysetHash [32]byte, at time.Time) error {
	atNanos := at.UTC().UnixNano()
	if len(rootPub) != ed25519.PublicKeySize ||
		!ed25519.Verify(rootPub, d.CanonicalBytes(), d.Sig) {
		return ErrDelegationBadSignature
	}
	if d.KeysetHash != keysetHash {
		return ErrDelegationKeysetMismatch
	}
	if atNanos < d.NotBefore {
		return ErrDelegationNotYetValid
	}
	if atNanos > d.NotAfter {
		return ErrDelegationExpired
	}
	return nil
}
