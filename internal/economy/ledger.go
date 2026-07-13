package economy

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sync"
)

// Sentinel errors returned (wrapped) by Open, Post, and Enact; branch with
// errors.Is. ErrConflict — the Store contract's own sentinel — is defined
// beside the Store interface; Post and Enact consume it internally during
// catch-up rather than surfacing it. All other failures (platform mismatch,
// zero amount, self-transfer, overflow, invalid genesis) return descriptive
// non-sentinel errors: they indicate programmer or configuration error, not
// caller-recoverable states.
var (
	ErrCreditDisabled = errors.New("economy: member credit disabled (ModeEscrow); enable via governed PolicyChange")
	ErrLimit          = errors.New("economy: spend would take the payer below the uniform debit cap")
	ErrSignature      = errors.New("economy: missing or invalid signature")
	ErrReplay         = errors.New("economy: nonce or policy version does not strictly advance")
	ErrUnknownAccount = errors.New("economy: directory cannot resolve account key")
	ErrQuorum         = errors.New("economy: policy change lacks threshold distinct steward signatures")
	ErrTampered       = errors.New("economy: store fails replay verification")
)

// Record is the sealed union of everything a Store can hold. The unexported
// method DETERS a third record kind (an "adjustment", a "mint", a fiat memo)
// but does not make one inexpressible: a foreign struct embedding a Spend or
// PolicyChange satisfies this interface from outside the package. What
// enforces the union is Open's EXACT-TYPE replay switch — replay matches on
// exactly Spend and exactly PolicyChange and rejects every other dynamic
// type with ErrTampered — so a smuggled kind can sit in a bypass-written
// store but can never replay into a live ledger.
type Record interface {
	CanonicalBytes() []byte
	record() // sealed
}

// Directory resolves member public keys out of band, mirroring the protocol's
// stance that keys are not distributed on the wire. The ledger cross-checks
// AccountIDFor(platform, pub) against the claimed AccountID, so a lying
// directory cannot substitute keys, and it rejects non-canonical key lengths
// before any signature verification, so a malformed directory cannot crash
// admission.
type Directory interface {
	// PublicKey returns the member key for an account, and whether it is known.
	PublicKey(a AccountID) (ed25519.PublicKey, bool)
}

// Ledger is the platform's credit ledger. The only mutations are Post and
// Enact, and both append — nothing updates or deletes. Balances are derived by
// folding over the store, never stored. Safe for concurrent use, including
// several Ledger instances sharing one Store: Append is conditional on
// position, so concurrent writers cannot fork history — a ledger that loses
// an append race first replays the unseen tail through the same admission
// rules Open uses, then retries.
type Ledger struct {
	mu       sync.Mutex
	genesis  Genesis
	dir      Directory
	store    Store
	pol      Policy
	version  uint64
	applied  int // records replayed or appended by this ledger; the Append position
	balances map[AccountID]int64
	nonces   map[AccountID]uint64
}

// Open validates g, then fully replays and verifies the store from genesis —
// every signature, platform binding, nonce, quorum, and admission rule under
// the policy in force at each record's position (positional, never
// retroactive) — and returns a live ledger; a tampered or bypass-written store
// fails with an error wrapping ErrTampered.
func Open(g Genesis, dir Directory, s Store) (*Ledger, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	if dir == nil {
		return nil, errors.New("economy: nil directory")
	}
	if s == nil {
		return nil, errors.New("economy: nil store")
	}
	l := &Ledger{
		genesis:  g,
		dir:      dir,
		store:    s,
		pol:      g.Policy,
		balances: make(map[AccountID]int64),
		nonces:   make(map[AccountID]uint64),
	}
	recs, err := s.All()
	if err != nil {
		return nil, fmt.Errorf("economy: reading store: %w", err)
	}
	for i, r := range recs {
		if err := l.replay(i, r); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// Post appends one payer-signed spend; it is the ONLY operation that moves
// credit. In ModeEscrow it returns ErrCreditDisabled. In ModeCredit it admits
// the spend iff Platform matches, From != To, Amount is positive and within
// int64 range, both From and To resolve in the Directory to canonical-length
// keys that hash to their claimed AccountIDs, the payer signature verifies,
// the Nonce strictly advances for From, and From's balance stays >=
// -DebitCap; then it appends and debits From and credits To equally, so the
// sum of balances is always zero. The append is conditional on this ledger's
// applied position: if another ledger over the same store won the race, Post
// replays the unseen tail through the same admission rules as Open and
// re-admits against the updated state, so a nonce spent through one ledger
// is ErrReplay through every other. ExchangeHash is opaque and deliberately
// unchecked here.
func (l *Ledger) Post(s Spend) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if err := l.admitSpend(s); err != nil {
			return err
		}
		err := l.store.Append(l.applied, s)
		if err == nil {
			l.applySpend(s)
			l.applied++
			return nil
		}
		if !errors.Is(err, ErrConflict) {
			return fmt.Errorf("economy: appending spend: %w", err)
		}
		if err := l.catchUp(); err != nil {
			return err
		}
	}
}

// Enact appends one quorum-verified policy change; it is the ONLY operation
// that alters policy, works identically in both modes, and rejects platform
// mismatch, version rollback (ErrReplay), sub-threshold signatures
// (ErrQuorum), and unknown modes. Like Post, its append is conditional and it
// catches up on ErrConflict before re-admitting, so a version enacted through
// one ledger is ErrReplay through every other. It affects subsequent Post
// calls only; no existing record is rewritten, revalidated, or reshaped.
func (l *Ledger) Enact(c PolicyChange) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if err := l.admitPolicyChange(c); err != nil {
			return err
		}
		err := l.store.Append(l.applied, c)
		if err == nil {
			l.applyPolicyChange(c)
			l.applied++
			return nil
		}
		if !errors.Is(err, ErrConflict) {
			return fmt.Errorf("economy: appending policy change: %w", err)
		}
		if err := l.catchUp(); err != nil {
			return err
		}
	}
}

// Policy returns the currently effective policy.
func (l *Ledger) Policy() Policy {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pol
}

// Balance returns the account's derived signed balance; zero for an account
// with no admitted spends.
func (l *Ledger) Balance(a AccountID) Balance {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Balance(l.balances[a])
}

// replay admits and applies r as the record at store position pos, advancing
// l.applied. It is the single fold step shared by Open's full replay and by
// catch-up after a lost append race, so a record cannot be admissible on one
// path yet unverifiable on the other. The type switch matches EXACTLY Spend
// and PolicyChange: any other dynamic type — including a foreign struct that
// smuggles into the Record union by embedding one of them — is rejected with
// ErrTampered. Caller holds l.mu.
func (l *Ledger) replay(pos int, r Record) error {
	switch rec := r.(type) {
	case Spend:
		if err := l.admitSpend(rec); err != nil {
			return fmt.Errorf("economy: replay position %d: %w: %v", pos, ErrTampered, err)
		}
		l.applySpend(rec)
	case PolicyChange:
		if err := l.admitPolicyChange(rec); err != nil {
			return fmt.Errorf("economy: replay position %d: %w: %v", pos, ErrTampered, err)
		}
		l.applyPolicyChange(rec)
	default:
		return fmt.Errorf("economy: replay position %d: %w: record kind %T is not a ledger value", pos, ErrTampered, r)
	}
	l.applied++
	return nil
}

// catchUp replays every store record this ledger has not yet applied, using
// the same fold step as Open. WHY: with several ledgers over one store, a
// conditional append fails with ErrConflict exactly when another writer got
// there first; replaying the unseen tail (rather than blindly retrying)
// rebuilds nonces, balances, and policy so re-admission judges the caller's
// record against true history. A tail that fails admission means the store
// was written outside a Ledger, and the error wraps ErrTampered. Caller
// holds l.mu.
func (l *Ledger) catchUp() error {
	recs, err := l.store.All()
	if err != nil {
		return fmt.Errorf("economy: reading store: %w", err)
	}
	if len(recs) < l.applied {
		return fmt.Errorf("economy: store holds %d records but %d were already applied: %w", len(recs), l.applied, ErrTampered)
	}
	for i := l.applied; i < len(recs); i++ {
		if err := l.replay(i, recs[i]); err != nil {
			return err
		}
	}
	return nil
}

// admitSpend checks every admission rule for s against the policy currently
// in force, mutating nothing. It is the single rule set shared by Post and by
// replay (Open and catch-up), so a spend cannot be admissible live yet
// unverifiable at reopen, or vice versa. Caller holds l.mu.
func (l *Ledger) admitSpend(s Spend) error {
	if l.pol.Mode == ModeEscrow {
		return ErrCreditDisabled
	}
	if s.Platform != l.genesis.Platform {
		return fmt.Errorf("economy: spend platform %q does not match ledger platform %q", s.Platform, l.genesis.Platform)
	}
	if s.From == s.To {
		return errors.New("economy: self-transfer: From equals To")
	}
	if s.Amount == 0 {
		return errors.New("economy: amount must be strictly positive")
	}
	if uint64(s.Amount) > math.MaxInt64 {
		return errors.New("economy: amount exceeds int64 range")
	}
	fromKey, ok := l.dir.PublicKey(s.From)
	if !ok {
		return fmt.Errorf("%w (payer)", ErrUnknownAccount)
	}
	// Reject non-canonical key lengths before any Verify, mirroring the
	// steward guard in PolicyChange.Verify. WHY: the Directory is
	// caller-supplied and ed25519.Verify panics on a key whose length is not
	// PublicKeySize, so an unguarded malformed key would crash Post and brick
	// Open's replay.
	if len(fromKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: directory key for payer has length %d, want %d", ErrSignature, len(fromKey), ed25519.PublicKeySize)
	}
	if AccountIDFor(l.genesis.Platform, fromKey) != s.From {
		return errors.New("economy: directory key for payer does not hash to the claimed account ID")
	}
	toKey, ok := l.dir.PublicKey(s.To)
	if !ok {
		return fmt.Errorf("%w (payee)", ErrUnknownAccount)
	}
	if len(toKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: directory key for payee has length %d, want %d", ErrSignature, len(toKey), ed25519.PublicKeySize)
	}
	if AccountIDFor(l.genesis.Platform, toKey) != s.To {
		return errors.New("economy: directory key for payee does not hash to the claimed account ID")
	}
	if !s.Verify(fromKey) {
		return ErrSignature
	}
	if s.Nonce <= l.nonces[s.From] {
		return fmt.Errorf("%w: spend nonce %d does not advance past %d", ErrReplay, s.Nonce, l.nonces[s.From])
	}
	amt := int64(s.Amount)
	from := l.balances[s.From]
	if from < math.MinInt64+amt {
		// Arithmetic underflow is unreachable below any representable cap.
		return fmt.Errorf("%w: payer balance would underflow", ErrLimit)
	}
	if from-amt < -int64(l.pol.DebitCap) {
		return fmt.Errorf("%w: balance %d - %d < -%d", ErrLimit, from, amt, l.pol.DebitCap)
	}
	if l.balances[s.To] > math.MaxInt64-amt {
		return errors.New("economy: payee balance would overflow int64")
	}
	return nil
}

// applySpend folds an admitted spend into the derived state: debit and credit
// are equal, so the sum of balances stays exactly zero. Caller holds l.mu.
func (l *Ledger) applySpend(s Spend) {
	amt := int64(s.Amount)
	l.balances[s.From] -= amt
	l.balances[s.To] += amt
	l.nonces[s.From] = s.Nonce
}

// admitPolicyChange checks every admission rule for c against the current
// version, mutating nothing; shared by Enact and replay (Open and catch-up).
// Caller holds l.mu.
func (l *Ledger) admitPolicyChange(c PolicyChange) error {
	if c.Platform != l.genesis.Platform {
		return fmt.Errorf("economy: policy change platform %q does not match ledger platform %q", c.Platform, l.genesis.Platform)
	}
	if c.Version <= l.version {
		return fmt.Errorf("%w: policy version %d does not advance past %d", ErrReplay, c.Version, l.version)
	}
	if err := c.Policy.validate(); err != nil {
		return err
	}
	if !c.Verify(l.genesis) {
		return ErrQuorum
	}
	return nil
}

// applyPolicyChange makes c the policy in force for subsequent admissions
// only; nothing already recorded is touched. Caller holds l.mu.
func (l *Ledger) applyPolicyChange(c PolicyChange) {
	l.pol = c.Policy
	l.version = c.Version
}
