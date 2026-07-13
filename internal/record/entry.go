package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
)

// Domain tags for the entry side of the record. One distinct unexported tag
// per message or derivation; every hash and signature payload in the package
// begins with exactly one tag, so no artifact is transferable between roles
// or message types (see doc.go for the full table).
const (
	domainContent = "drops/content/v0"
	domainEntry   = "drops/entry/v0"
	domainLeaf    = "drops/leaf/v0"
)

// Hash is an opaque 32-byte SHA-256 digest: the only value other Cloudy
// layers may hold to reference anything in this package (cross-layer
// references are by value, never by type import). The value other JFA layers
// carry as their opaque exchange reference is the record entry's leaf ID,
// Entry.ID() — never the Content hash.
type Hash [32]byte

// zeroHash is the absent reference: a zero Corrects marks a plain covenant.
var zeroHash Hash

// HashContent digests member-local content under the content domain tag; the
// bytes are consumed into the digest and never retained — this and
// Locker.Put are the package's ONLY ingress for identifying content.
func HashContent(content []byte) Hash {
	return Hash(sha256.Sum256(canon.New(domainContent).Bytes(content).Sum()))
}

// LogID derives a log's identity from its operator's public key — derived,
// never chosen, so it cannot carry text and cannot be squatted; it seeds the
// log's hash chain and scopes every entry and checkpoint.
func LogID(operator ed25519.PublicKey) Hash {
	return Hash(sha256.Sum256(canon.New(domainChain).Bytes(operator).Sum()))
}

// Entry is one dialog-sealed covenant between two members: fixed-size
// hashes, keys, a random nonce, and a UTC instant — no string field and no
// open byte field exists, so PII cannot be expressed in the commons.
type Entry struct {
	Log      Hash              // LogID of the one operator log this covenant may enter; inside the signed bytes, so cross-log replay is dead
	Proposer ed25519.PublicKey // member who proposed the covenant
	Acceptor ed25519.PublicKey // member who accepted it; MUST differ from Proposer
	Content  Hash              // HashContent of the erasable, member-local narrative; the content itself never enters the commons
	Corrects Hash              // ID of the prior in-log entry this corrects; zero Hash when not a correction — corrections add, never replace
	Nonce    [32]byte          // random; makes textually identical covenants distinct entries and re-appends detectable
	SealedAt time.Time         // UTC claim signed by both parties; the log neither validates nor orders by it — Seq is the only order

	ProposerSeal []byte // ed25519 by Proposer over CanonicalBytes; excluded from CanonicalBytes
	AcceptorSeal []byte // ed25519 by Acceptor over CanonicalBytes; excluded from CanonicalBytes
}

// NewEntry builds an unsigned covenant bound to log, drawing Nonce from
// crypto/rand; corrects is the zero Hash for a plain covenant; it errors on
// proposer == acceptor or malformed keys.
func NewEntry(log Hash, proposer, acceptor ed25519.PublicKey, content, corrects Hash, at time.Time) (Entry, error) {
	if len(proposer) != ed25519.PublicKeySize {
		return Entry{}, errors.New("record: proposer key is malformed")
	}
	if len(acceptor) != ed25519.PublicKeySize {
		return Entry{}, errors.New("record: acceptor key is malformed")
	}
	if bytes.Equal(proposer, acceptor) {
		return Entry{}, errors.New("record: proposer and acceptor must be distinct members (no self-dialog)")
	}
	e := Entry{
		Log:      log,
		Proposer: append(ed25519.PublicKey(nil), proposer...),
		Acceptor: append(ed25519.PublicKey(nil), acceptor...),
		Content:  content,
		Corrects: corrects,
		SealedAt: at,
	}
	if _, err := rand.Read(e.Nonce[:]); err != nil {
		return Entry{}, fmt.Errorf("record: drawing nonce: %w", err)
	}
	return e, nil
}

// CanonicalBytes returns the deterministic signing payload (canon encoding,
// entry domain tag) with both seals excluded.
func (e Entry) CanonicalBytes() []byte {
	b := canon.New(domainEntry)
	b.Bytes(e.Log[:])
	b.Bytes(e.Proposer)
	b.Bytes(e.Acceptor)
	b.Bytes(e.Content[:])
	b.Bytes(e.Corrects[:])
	b.Bytes(e.Nonce[:])
	b.Time(e.SealedAt)
	return b.Sum()
}

// Seal signs with priv and fills whichever seal slot matches the derived
// public key; it errors if the key is neither party — signing the wrong slot
// is inexpressible.
func (e *Entry) Seal(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("record: sealing key is malformed")
	}
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, e.CanonicalBytes())
	switch {
	case bytes.Equal(pub, e.Proposer):
		e.ProposerSeal = sig
	case bytes.Equal(pub, e.Acceptor):
		e.AcceptorSeal = sig
	default:
		return errors.New("record: sealing key is neither proposer nor acceptor")
	}
	return nil
}

// Verify reports whether Proposer and Acceptor are distinct well-formed keys
// and BOTH seals verify over CanonicalBytes — a half-sealed or self-dealt
// entry never verifies and is not a record.
func (e Entry) Verify() bool {
	if len(e.Proposer) != ed25519.PublicKeySize || len(e.Acceptor) != ed25519.PublicKeySize {
		return false
	}
	if bytes.Equal(e.Proposer, e.Acceptor) {
		return false
	}
	if len(e.ProposerSeal) != ed25519.SignatureSize || len(e.AcceptorSeal) != ed25519.SignatureSize {
		return false
	}
	msg := e.CanonicalBytes()
	return ed25519.Verify(e.Proposer, msg, e.ProposerSeal) &&
		ed25519.Verify(e.Acceptor, msg, e.AcceptorSeal)
}

// ID returns the entry's leaf hash (leaf domain tag, over canonical bytes
// plus both seals); it is what Corrects, proofs, and the other JFA layers
// reference — the record entry's leaf ID is THE cross-layer exchange
// reference, and the Content hash is not.
func (e Entry) ID() Hash {
	b := canon.New(domainLeaf)
	b.Bytes(e.CanonicalBytes())
	b.Bytes(e.ProposerSeal)
	b.Bytes(e.AcceptorSeal)
	return Hash(sha256.Sum256(b.Sum()))
}
