// Package composition_test is the composition-root integration test: the one
// test in the tree that imports all three JFA member-economy packages
// (internal/economy, internal/covenant, internal/record), which never import
// each other. Everything the coherence directives assign to the composition
// root is implemented here as test scaffolding:
//
//   - the single shared member directory backing economy.Directory,
//     covenant.Directory, and the key comparisons inside the Anchors
//     predicate — one keypair answers for a member's AccountID, MemberID,
//     and record-layer public key;
//   - the covenant.Anchors predicate wired to the operator's record log,
//     joining covenant to record on Entry.ID(), the record entry's leaf ID;
//   - all conversions between the layers' [32]byte reference types
//     (record.Hash -> economy Spend.ExchangeHash / covenant.ExchangeRef).
//
// cmd/cloudy performs the same composition at startup; no internal package
// ever sees more than its own types.
package composition_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/dispute"
	"github.com/NTARI-RAND/Cloudy/internal/economy"
	"github.com/NTARI-RAND/Cloudy/internal/record"
)

// platform is the sovereign platform identity every ID and record in these
// tests is scoped to.
const platform = "cloudy"

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pub, priv
}

// memberDirectory is the single shared member directory the coherence
// directives require at the composition root: one keypair registry that
// answers for a member's economy.AccountID, covenant.MemberID, and
// record-layer public key. No JFA package stores, distributes, or derives
// keys for another; each resolves keys out-of-band through a typed view of
// this one registry.
type memberDirectory struct {
	platform  string
	byAccount map[economy.AccountID]ed25519.PublicKey
	byMember  map[covenant.MemberID]ed25519.PublicKey
}

func newMemberDirectory(platform string) *memberDirectory {
	return &memberDirectory{
		platform:  platform,
		byAccount: make(map[economy.AccountID]ed25519.PublicKey),
		byMember:  make(map[covenant.MemberID]ed25519.PublicKey),
	}
}

// register mints the member's two platform-scoped IDs from one public key —
// the composition root is the only place MemberIDs are minted, per covenant's
// forbidden-human-chosen-IDs rule. The directory stores its OWN copy of the
// key: a caller later mutating the buffer it registered must not silently
// break resolution everywhere (same defensive discipline the internal
// packages apply to signature and key slices).
func (d *memberDirectory) register(pub ed25519.PublicKey) (economy.AccountID, covenant.MemberID) {
	acct := economy.AccountIDFor(d.platform, pub)
	member := covenant.MemberIDFor(d.platform, pub)
	owned := append(ed25519.PublicKey(nil), pub...)
	d.byAccount[acct] = owned
	d.byMember[member] = owned
	return acct, member
}

// economyDirectory and covenantDirectory are typed views over the one shared
// registry: Go method sets cannot overload PublicKey by ID type, so each JFA
// package sees the same directory through its own adapter. Every adapter
// returns a COPY of the registered key, so no caller can corrupt the registry
// through a returned slice.
type economyDirectory struct{ d *memberDirectory }

func (v economyDirectory) PublicKey(a economy.AccountID) (ed25519.PublicKey, bool) {
	pub, ok := v.d.byAccount[a]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}

type covenantDirectory struct{ d *memberDirectory }

func (v covenantDirectory) PublicKey(m covenant.MemberID) (ed25519.PublicKey, bool) {
	pub, ok := v.d.byMember[m]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}

// recordAnchors implements covenant.Anchors exactly as the coherence
// directive specifies: resolve both MemberIDs to public keys via the shared
// directory, locate the entry whose ID() equals the ExchangeRef in the local
// operator's record log (the root keeps its own ID->seq index; record exports
// none by design), and return true only if the entry is bound to THIS
// operator log (e.Log == logID — defense in depth against a bypass-written
// or hostile store; Log.Append already refuses foreign-log entries), fully
// Verify()s, and its Proposer/Acceptor keys equal exactly the resolved pair,
// in either order.
type recordAnchors struct {
	dir   *memberDirectory
	store record.Store
	logID record.Hash            // LogID of the one operator log entries may anchor to
	index map[record.Hash]uint64 // Entry.ID() -> sequence in the operator's log
}

func newRecordAnchors(dir *memberDirectory, store record.Store, logID record.Hash) *recordAnchors {
	return &recordAnchors{dir: dir, store: store, logID: logID, index: make(map[record.Hash]uint64)}
}

// noteAppended maintains the root's own ID->sequence index; called after
// every successful Log.Append.
func (a *recordAnchors) noteAppended(id record.Hash, seq uint64) {
	a.index[id] = seq
}

func (a *recordAnchors) Sealed(exchange covenant.ExchangeRef, assessor, subject covenant.MemberID) bool {
	assessorKey, ok := a.dir.byMember[assessor]
	if !ok {
		return false
	}
	subjectKey, ok := a.dir.byMember[subject]
	if !ok {
		return false
	}
	// The [32]byte conversion between the layers' reference types happens
	// here, at the composition root, and nowhere else.
	id := record.Hash(exchange)
	seq, ok := a.index[id]
	if !ok {
		return false
	}
	e, err := a.store.At(seq)
	if err != nil || e.ID() != id || e.Log != a.logID || !e.Verify() {
		return false
	}
	return (bytes.Equal(e.Proposer, assessorKey) && bytes.Equal(e.Acceptor, subjectKey)) ||
		(bytes.Equal(e.Proposer, subjectKey) && bytes.Equal(e.Acceptor, assessorKey))
}

// disputeAnchors implements dispute.Anchors. It is the dispute-side twin of
// recordAnchors: same join to the operator's record log on Entry.ID(), but the
// dispute port speaks raw ed25519 public keys (not covenant MemberIDs), so the
// party match compares the resolved keys directly. It REUSES the root's one
// Entry.ID()->seq index — the same map recordAnchors holds — so a single index
// serves both cross-layer joins; the [32]byte conversion between record.Hash
// and dispute.ExchangeRef happens here and nowhere else.
type disputeAnchors struct {
	store record.Store
	logID record.Hash
	index map[record.Hash]uint64 // shared with recordAnchors
}

func (a *disputeAnchors) Sealed(exchange dispute.ExchangeRef, complainant, respondent ed25519.PublicKey) bool {
	id := record.Hash(exchange)
	seq, ok := a.index[id]
	if !ok {
		return false
	}
	e, err := a.store.At(seq)
	if err != nil || e.ID() != id || e.Log != a.logID || !e.Verify() {
		return false
	}
	return (bytes.Equal(e.Proposer, complainant) && bytes.Equal(e.Acceptor, respondent)) ||
		(bytes.Equal(e.Proposer, respondent) && bytes.Equal(e.Acceptor, complainant))
}

// disputeMode maps the economy ledger's policy mode to dispute's DISTINCT
// local Mode type. This is the ONLY place the two mode vocabularies meet;
// dispute never imports economy, so the seam reads ledger.Policy().Mode and
// hands the ruling the corresponding dispute.Mode.
func disputeMode(t *testing.T, m economy.Mode) dispute.Mode {
	t.Helper()
	switch m {
	case economy.ModeEscrow:
		return dispute.ModeEscrow
	case economy.ModeCredit:
		return dispute.ModeCredit
	}
	t.Fatalf("unmappable economy mode %q", m)
	return 0
}

// Compile-time proof that the shared scaffolding satisfies each package's
// out-of-band ports.
var (
	_ economy.Directory  = economyDirectory{}
	_ covenant.Directory = covenantDirectory{}
	_ covenant.Anchors   = (*recordAnchors)(nil)
	_ dispute.Anchors    = (*disputeAnchors)(nil)
)

// stack is one fully composed Cloudy: the three JFA layers over the single
// shared member directory. The economy ALWAYS opens at a ModeEscrow genesis;
// the escrow->credit transition is exactly one quorum-signed PolicyChange
// (enactCredit).
type stack struct {
	dir      *memberDirectory
	recStore *record.MemStore
	log      *record.Log
	anchors  *recordAnchors
	ledger   *economy.Ledger
	book     *covenant.Book
	genesis  economy.Genesis
	stewards []ed25519.PrivateKey
}

func newStack(t *testing.T, dir *memberDirectory, operator ed25519.PublicKey, stewards []ed25519.PrivateKey, threshold int) *stack {
	t.Helper()
	recStore := record.NewMemStore()
	l, err := record.OpenLog(operator, recStore)
	if err != nil {
		t.Fatalf("opening record log: %v", err)
	}
	stewardPubs := make([]ed25519.PublicKey, len(stewards))
	for i, s := range stewards {
		stewardPubs[i] = s.Public().(ed25519.PublicKey)
	}
	genesis := economy.Genesis{
		Platform:  dir.platform,
		Stewards:  stewardPubs,
		Threshold: threshold,
		Policy:    economy.Policy{Mode: economy.ModeEscrow},
	}
	ledger, err := economy.Open(genesis, economyDirectory{dir}, economy.NewMemStore())
	if err != nil {
		t.Fatalf("opening economy ledger: %v", err)
	}
	anchors := newRecordAnchors(dir, recStore, record.LogID(operator))
	// The platform string handed to NewBook is the SAME platform the economy
	// Genesis is scoped to and the same one register mints IDs under — Record
	// re-derives every MemberID from the directory key under it. The nil
	// categories slice takes the LBTAS default closed vocabulary:
	// reliability, usability, performance, support.
	book, err := covenant.NewBook(dir.platform, nil, covenantDirectory{dir}, anchors, covenant.NewMemStore())
	if err != nil {
		t.Fatalf("opening covenant book: %v", err)
	}
	return &stack{
		dir:      dir,
		recStore: recStore,
		log:      l,
		anchors:  anchors,
		ledger:   ledger,
		book:     book,
		genesis:  genesis,
		stewards: stewards,
	}
}

// appendEntry is the root's append path: Log.Append plus maintenance of the
// root's own ID->seq index for the Anchors predicate.
func (s *stack) appendEntry(t *testing.T, e record.Entry) uint64 {
	t.Helper()
	seq, err := s.log.Append(e)
	if err != nil {
		t.Fatalf("appending entry: %v", err)
	}
	s.anchors.noteAppended(e.ID(), seq)
	return seq
}

// enactCredit flips escrow->credit with exactly one quorum-signed
// PolicyChange — the one-switch transition, itself an auditable ledger record.
func (s *stack) enactCredit(t *testing.T, cap economy.Amount, version uint64, at time.Time) {
	t.Helper()
	change := economy.PolicyChange{
		Platform: s.genesis.Platform,
		Policy:   economy.Policy{Mode: economy.ModeCredit, DebitCap: cap},
		Version:  version,
		At:       at,
	}
	for i := 0; i < s.genesis.Threshold; i++ {
		change.Sign(s.stewards[i])
	}
	if err := s.ledger.Enact(change); err != nil {
		t.Fatalf("enacting escrow->credit policy change: %v", err)
	}
}

// sealEntry builds and dual-seals a covenant entry between two members.
func sealEntry(t *testing.T, logID record.Hash, proposerPub ed25519.PublicKey, proposerPriv ed25519.PrivateKey, acceptorPub ed25519.PublicKey, acceptorPriv ed25519.PrivateKey, content record.Hash, at time.Time) record.Entry {
	t.Helper()
	e, err := record.NewEntry(logID, proposerPub, acceptorPub, content, record.Hash{}, at)
	if err != nil {
		t.Fatalf("building entry: %v", err)
	}
	if err := e.Seal(proposerPriv); err != nil {
		t.Fatalf("proposer seal: %v", err)
	}
	if err := e.Seal(acceptorPriv); err != nil {
		t.Fatalf("acceptor seal: %v", err)
	}
	if !e.Verify() {
		t.Fatal("dual-sealed entry does not verify")
	}
	return e
}

// TestSharedDirectoryOneKeypairEverywhere pins the directive that one
// composition-root member directory backs everything: the same keypair
// answers for a member's economy AccountID and covenant MemberID, while the
// two IDs themselves — derived under distinct package-owned domain tags — do
// not trivially equate.
func TestSharedDirectoryOneKeypairEverywhere(t *testing.T) {
	pub, _ := genKey(t)
	dir := newMemberDirectory(platform)
	acct, member := dir.register(pub)

	got, ok := economyDirectory{dir}.PublicKey(acct)
	if !ok || !bytes.Equal(got, pub) {
		t.Fatal("economy view of the shared directory does not resolve the registered key")
	}
	got, ok = covenantDirectory{dir}.PublicKey(member)
	if !ok || !bytes.Equal(got, pub) {
		t.Fatal("covenant view of the shared directory does not resolve the registered key")
	}
	// cloudy/economy/acct/v0 vs cloudy/covenant/member/v0: same key, same
	// platform, different derivations — the IDs must not equate.
	if hex.EncodeToString(acct[:]) == string(member) {
		t.Fatal("economy AccountID and covenant MemberID trivially equate; domain tags are not separating the derivations")
	}
}

// TestMemberStoryEndToEnd exercises the full composed member story:
//
//	seal a record Entry between two members -> operator appends, checkpoints,
//	a witness countersigns -> post an economy Spend carrying entry.ID() as
//	ExchangeHash (in ModeCredit, reached by one quorum PolicyChange from a
//	ModeEscrow genesis) -> record LBTAS covenant Assessments in both
//	directions anchored to entry.ID(), then a No Trust (-1) verdict whose
//	justifying comment lives only in an erasable record Locker while its hash
//	rides in the commons -> erase the comment -> assert per-category and
//	Overall Standing distributions and the Harm() surfacing.
func TestMemberStoryEndToEnd(t *testing.T) {
	alicePub, alicePriv := genKey(t)
	bobPub, bobPriv := genKey(t)
	operatorPub, operatorPriv := genKey(t)
	_, witnessPriv := genKey(t)
	var stewards []ed25519.PrivateKey
	for i := 0; i < 3; i++ {
		_, priv := genKey(t)
		stewards = append(stewards, priv)
	}

	dir := newMemberDirectory(platform)
	aliceAcct, aliceMember := dir.register(alicePub)
	bobAcct, bobMember := dir.register(bobPub)
	st := newStack(t, dir, operatorPub, stewards, 2)

	// --- record: two members seal a covenant; the narrative stays in the
	// erasable member-local locker, only its hash enters the commons.
	locker := record.NewMemLocker()
	content := locker.Put([]byte("alice tunes bob's antenna array; bob owes alice seven units of cloudy credit"))
	entry := sealEntry(t, record.LogID(operatorPub), alicePub, alicePriv, bobPub, bobPriv, content, time.Now().UTC())
	seq := st.appendEntry(t, entry)

	// Operator checkpoints; an independent witness countersigns; the member
	// holds an offline-verifiable inclusion proof.
	cp := st.log.Checkpoint(time.Now().UTC())
	cp.Sign(operatorPriv)
	w := record.NewWitness(witnessPriv)
	cs, err := w.Countersign(cp, operatorPub, nil)
	if err != nil {
		t.Fatalf("witness countersign: %v", err)
	}
	wcp := record.WitnessedCheckpoint{Checkpoint: cp, Countersignatures: []record.Countersignature{cs}}
	if !wcp.Verify(operatorPub) {
		t.Fatal("witnessed checkpoint does not verify")
	}
	// StandIn now counts only verified, operator-independent cosignatures;
	// one genuine independent witness is still below the federation floor.
	if !wcp.StandIn(operatorPub) {
		t.Fatal("a single-witness checkpoint must carry the stand-in label")
	}
	proof, err := st.log.Prove(seq)
	if err != nil {
		t.Fatalf("proving inclusion: %v", err)
	}
	if !record.VerifyInclusion(entry, proof, cp, operatorPub) {
		t.Fatal("inclusion proof for the sealed entry does not verify")
	}

	// --- economy: the ModeEscrow genesis refuses credit; the spend is signed
	// once and carries entry.ID() — the record entry's leaf ID — as its opaque
	// ExchangeHash (converted here, at the composition root).
	spend := economy.Spend{
		Platform:     platform,
		From:         aliceAcct,
		To:           bobAcct,
		Amount:       7,
		ExchangeHash: [32]byte(entry.ID()),
		IssuedAt:     time.Now().UTC(),
		Nonce:        1,
	}
	spend.Sign(alicePriv)
	if err := st.ledger.Post(spend); !errors.Is(err, economy.ErrCreditDisabled) {
		t.Fatalf("Post under ModeEscrow: got %v, want ErrCreditDisabled", err)
	}

	// One quorum-signed PolicyChange is the entire escrow->credit transition;
	// the identical signed spend is admitted after the flip.
	st.enactCredit(t, 100, 1, time.Now().UTC())
	if got := st.ledger.Policy().Mode; got != economy.ModeCredit {
		t.Fatalf("policy mode after flip: got %q, want %q", got, economy.ModeCredit)
	}
	if err := st.ledger.Post(spend); err != nil {
		t.Fatalf("Post under ModeCredit: %v", err)
	}
	if got := st.ledger.Balance(aliceAcct); got != -7 {
		t.Fatalf("payer balance: got %d, want -7", got)
	}
	if got := st.ledger.Balance(bobAcct); got != 7 {
		t.Fatalf("payee balance: got %d, want 7", got)
	}
	if sum := st.ledger.Balance(aliceAcct) + st.ledger.Balance(bobAcct); sum != 0 {
		t.Fatalf("sum of balances: got %d, want exactly 0", sum)
	}

	// --- covenant: LBTAS assessments in both directions — the scale is
	// bidirectional, so one sealed exchange grounds a verdict each way — each
	// anchored to the same entry.ID() under a category of the Book's closed
	// default vocabulary; the two directions exercise both orders of the
	// Anchors proposer/acceptor match.
	ref := covenant.ExchangeRef(entry.ID())
	aToB := covenant.Assessment{
		Assessor: aliceMember,
		Subject:  bobMember,
		Exchange: ref,
		Category: "reliability",
		Level:    covenant.LevelDelight,
		IssuedAt: time.Now().UTC(),
	}
	aToB.Sign(alicePriv)
	if err := st.book.Record(aToB); err != nil {
		t.Fatalf("recording alice->bob assessment: %v", err)
	}
	bToA := covenant.Assessment{
		Assessor: bobMember,
		Subject:  aliceMember,
		Exchange: ref,
		Category: "reliability",
		Level:    covenant.LevelBasicSatisfaction,
		IssuedAt: time.Now().UTC(),
	}
	bToA.Sign(bobPriv)
	if err := st.book.Record(bToA); err != nil {
		t.Fatalf("recording bob->alice assessment: %v", err)
	}

	// --- covenant, the -1 path: a No Trust verdict must carry a justifying
	// comment, and the no-PII reconciliation is exercised end to end here —
	// the comment TEXT lives only in the erasable member-local record Locker,
	// while the commons carries just its hash (record.HashContent, converted
	// to covenant's [32]byte at this composition root, like every other
	// cross-layer conversion). Same exchange, different category, so
	// per-(assessor, exchange, category) uniqueness admits it alongside
	// alice's reliability verdict.
	comment := []byte("bob's support channel went dark for three weeks after payment and no remedy was offered")
	commentLocker := record.NewMemLocker()
	commentHash := commentLocker.Put(comment)
	if commentHash != record.HashContent(comment) {
		t.Fatal("Locker.Put and HashContent disagree on the comment hash")
	}
	noTrust := covenant.Assessment{
		Assessor:    aliceMember,
		Subject:     bobMember,
		Exchange:    ref,
		Category:    "support",
		Level:       covenant.LevelNoTrust,
		CommentHash: [32]byte(commentHash),
		IssuedAt:    time.Now().UTC(),
	}
	noTrust.Sign(alicePriv)
	if err := st.book.Record(noTrust); err != nil {
		t.Fatalf("recording alice->bob No Trust assessment: %v", err)
	}
	// The member erases the comment; the commons keeps only the hash, and the
	// admitted verdict — and its harm signal — must not notice.
	commentLocker.Erase(commentHash)
	if _, held := commentLocker.Get(commentHash); held {
		t.Fatal("comment text still held in the locker after erasure")
	}

	// Standing is the full LBTAS read shape: per-category distributions plus
	// the pooled overall, counts only, never a mean — and the erased comment
	// leaves the admitted -1 surfaced by Harm().
	assertDist := func(d covenant.Distribution, want map[covenant.Level]int) {
		t.Helper()
		total := 0
		for _, n := range want {
			total += n
		}
		if d.Total() != total {
			t.Fatalf("distribution total: got %d, want %d", d.Total(), total)
		}
		for _, l := range covenant.Levels() {
			if got := d.Count(l); got != want[l] {
				t.Fatalf("distribution count at %q: got %d, want %d", l, got, want[l])
			}
		}
	}
	bobStanding, err := st.book.Standing(bobMember)
	if err != nil {
		t.Fatalf("bob standing: %v", err)
	}
	assertDist(bobStanding.Category("reliability"), map[covenant.Level]int{covenant.LevelDelight: 1})
	assertDist(bobStanding.Category("support"), map[covenant.Level]int{covenant.LevelNoTrust: 1})
	assertDist(bobStanding.Overall(), map[covenant.Level]int{
		covenant.LevelDelight: 1,
		covenant.LevelNoTrust: 1,
	})
	if got := bobStanding.Total(); got != 2 {
		t.Fatalf("bob standing total: got %d, want 2", got)
	}
	if got := bobStanding.Harm(); got != 1 {
		t.Fatalf("bob Harm(): got %d, want 1 — the -1 must stay surfaced after its comment text is erased", got)
	}
	aliceStanding, err := st.book.Standing(aliceMember)
	if err != nil {
		t.Fatalf("alice standing: %v", err)
	}
	assertDist(aliceStanding.Category("reliability"), map[covenant.Level]int{covenant.LevelBasicSatisfaction: 1})
	assertDist(aliceStanding.Overall(), map[covenant.Level]int{covenant.LevelBasicSatisfaction: 1})
	if got := aliceStanding.Harm(); got != 0 {
		t.Fatalf("alice Harm(): got %d, want 0", got)
	}
}

// TestModeIndependence pins coherence directive 9: sealing an Entry and
// recording an Assessment are byte-identical operations whether the economy
// ledger is in ModeEscrow or ModeCredit — no package branches on, encodes, or
// infers another package's state. The ONLY difference between the two runs is
// the outcome of the Post: refused under escrow, admitted under credit.
func TestModeIndependence(t *testing.T) {
	alicePub, alicePriv := genKey(t)
	bobPub, bobPriv := genKey(t)
	operatorPub, _ := genKey(t)
	_, stewardPriv := genKey(t)
	stewards := []ed25519.PrivateKey{stewardPriv}

	dir := newMemberDirectory(platform)
	aliceAcct, aliceMember := dir.register(alicePub)
	bobAcct, bobMember := dir.register(bobPub)

	// Fixed inputs shared by both runs. The Entry is built literally (not via
	// NewEntry) so its nonce is fixed; ed25519 signing is deterministic, so
	// identical inputs must yield identical seals and signatures.
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	entryTemplate := record.Entry{
		Log:      record.LogID(operatorPub),
		Proposer: alicePub,
		Acceptor: bobPub,
		Content:  record.HashContent([]byte("fixed narrative for the mode-independence check")),
		Corrects: record.Hash{},
		Nonce:    nonce,
		SealedAt: at,
	}

	type run struct {
		entryCanon   []byte
		proposerSeal []byte
		acceptorSeal []byte
		entryID      record.Hash
		assessCanon  []byte
		assessSig    []byte
		postErr      error
	}

	do := func(credit bool) run {
		t.Helper()
		st := newStack(t, dir, operatorPub, stewards, 1)
		if credit {
			st.enactCredit(t, 100, 1, at)
		}
		e := entryTemplate
		if err := e.Seal(alicePriv); err != nil {
			t.Fatalf("proposer seal: %v", err)
		}
		if err := e.Seal(bobPriv); err != nil {
			t.Fatalf("acceptor seal: %v", err)
		}
		st.appendEntry(t, e)

		a := covenant.Assessment{
			Assessor: aliceMember,
			Subject:  bobMember,
			Exchange: covenant.ExchangeRef(e.ID()),
			Category: "performance",
			Level:    covenant.LevelNoNegativeConsequences,
			IssuedAt: at,
		}
		a.Sign(alicePriv)
		if err := st.book.Record(a); err != nil {
			t.Fatalf("recording assessment (credit=%v): %v", credit, err)
		}

		sp := economy.Spend{
			Platform:     platform,
			From:         aliceAcct,
			To:           bobAcct,
			Amount:       3,
			ExchangeHash: [32]byte(e.ID()),
			IssuedAt:     at,
			Nonce:        1,
		}
		sp.Sign(alicePriv)
		return run{
			entryCanon:   e.CanonicalBytes(),
			proposerSeal: e.ProposerSeal,
			acceptorSeal: e.AcceptorSeal,
			entryID:      e.ID(),
			assessCanon:  a.CanonicalBytes(),
			assessSig:    a.Signature,
			postErr:      st.ledger.Post(sp),
		}
	}

	escrow := do(false)
	credit := do(true)

	// What the byte-equality checks below do and do NOT prove. Every compared
	// artifact (entry canonical bytes, both seals, the leaf ID, assessment
	// canonical bytes, the assessment signature) is computed by record/covenant
	// from fixed caller-supplied inputs whose types cannot even mention ledger
	// state, and ed25519 signing is deterministic — so under the current APIs
	// no realizable mode-coupling can make them differ, and these assertions
	// alone can only fail if sealing/signing itself becomes nondeterministic.
	// They pin the API SHAPE (sealing and assessing take no ledger input); the
	// assertions with behavioral teeth are that Append and Record SUCCEED
	// identically inside both do() runs and that only the Post outcome differs
	// (below). Structural non-coupling — that record/covenant cannot see
	// economy at all — is pinned separately by TestImportGraph.
	if !bytes.Equal(escrow.entryCanon, credit.entryCanon) {
		t.Fatal("entry canonical bytes differ across ledger modes")
	}
	if !bytes.Equal(escrow.proposerSeal, credit.proposerSeal) ||
		!bytes.Equal(escrow.acceptorSeal, credit.acceptorSeal) {
		t.Fatal("entry seals differ across ledger modes")
	}
	if escrow.entryID != credit.entryID {
		t.Fatal("entry leaf IDs differ across ledger modes")
	}
	if !bytes.Equal(escrow.assessCanon, credit.assessCanon) {
		t.Fatal("assessment canonical bytes differ across ledger modes")
	}
	if !bytes.Equal(escrow.assessSig, credit.assessSig) {
		t.Fatal("assessment signatures differ across ledger modes")
	}
	// Only the Post differs.
	if !errors.Is(escrow.postErr, economy.ErrCreditDisabled) {
		t.Fatalf("escrow Post: got %v, want ErrCreditDisabled", escrow.postErr)
	}
	if credit.postErr != nil {
		t.Fatalf("credit Post: got %v, want admission", credit.postErr)
	}
}

// TestNegativeJoins pins the deliberate asymmetry between the two cross-layer
// joins: covenant assessments are anchored (a fabricated ExchangeRef is
// rejected at the Anchors gate), while economy spends are not (a fabricated
// ExchangeHash is admitted).
func TestNegativeJoins(t *testing.T) {
	alicePub, alicePriv := genKey(t)
	bobPub, bobPriv := genKey(t)
	carolPub, carolPriv := genKey(t)
	operatorPub, _ := genKey(t)
	_, stewardPriv := genKey(t)

	dir := newMemberDirectory(platform)
	aliceAcct, aliceMember := dir.register(alicePub)
	bobAcct, bobMember := dir.register(bobPub)
	_, carolMember := dir.register(carolPub)
	st := newStack(t, dir, operatorPub, []ed25519.PrivateKey{stewardPriv}, 1)
	st.enactCredit(t, 100, 1, time.Now().UTC())

	// One real sealed entry between alice and bob.
	entry := sealEntry(t, record.LogID(operatorPub), alicePub, alicePriv, bobPub, bobPriv,
		record.HashContent([]byte("a real exchange")), time.Now().UTC())
	st.appendEntry(t, entry)

	// A fabricated (nonzero) exchange reference naming no sealed entry.
	var fabricated covenant.ExchangeRef
	for i := range fabricated {
		fabricated[i] = 0xAB
	}
	if st.anchors.Sealed(fabricated, aliceMember, bobMember) {
		t.Fatal("Anchors reports a fabricated reference as sealed")
	}
	fake := covenant.Assessment{
		Assessor: aliceMember,
		Subject:  bobMember,
		Exchange: fabricated,
		Category: "reliability",
		Level:    covenant.LevelBasicPromise,
		IssuedAt: time.Now().UTC(),
	}
	fake.Sign(alicePriv)
	err := st.book.Record(fake)
	if !errors.Is(err, covenant.ErrInvalid) {
		t.Fatalf("assessment with fabricated ExchangeRef: got %v, want ErrInvalid", err)
	}
	if err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("rejection must come from the Anchors gate, got: %v", err)
	}

	// A real entry, but the assessor was no party to it: same gate.
	byStranger := covenant.Assessment{
		Assessor: carolMember,
		Subject:  bobMember,
		Exchange: covenant.ExchangeRef(entry.ID()),
		Category: "reliability",
		Level:    covenant.LevelBasicPromise,
		IssuedAt: time.Now().UTC(),
	}
	byStranger.Sign(carolPriv)
	err = st.book.Record(byStranger)
	if !errors.Is(err, covenant.ErrInvalid) || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("assessment by a non-party: got %v, want Anchors-gate ErrInvalid", err)
	}

	// A spend to the same fabricated hash IS admitted: economy deliberately
	// does not anchor. internal/economy/doc.go names this asymmetry in its
	// "The cross-layer reference" section (lines 79-84): ExchangeHash "is
	// opaque and UNCHECKED at Post: this package never parses it, never
	// resolves it, and never verifies that it names a real sealed entry. A
	// fabricated hash only spends the payer's own capped credit." Anchoring,
	// if ever wanted, is a composition-root concern — this test IS that root,
	// and it deliberately leaves spends unanchored.
	sp := economy.Spend{
		Platform:     platform,
		From:         aliceAcct,
		To:           bobAcct,
		Amount:       2,
		ExchangeHash: [32]byte(fabricated),
		IssuedAt:     time.Now().UTC(),
		Nonce:        1,
	}
	sp.Sign(alicePriv)
	if err := st.ledger.Post(sp); err != nil {
		t.Fatalf("spend to a fabricated hash must be admitted (economy/doc.go: opaque and UNCHECKED at Post), got: %v", err)
	}
	if got := st.ledger.Balance(aliceAcct); got != -2 {
		t.Fatalf("payer balance after fabricated-hash spend: got %d, want -2 (only the payer's own capped credit)", got)
	}
}

// TestDirectoryKeyCopies pins the composition root's defensive-copy
// discipline for the shared member directory: the registry owns its key
// bytes. Registering a key and then mutating the caller's buffer must not
// break resolution, and mutating a key RETURNED by an adapter must not
// corrupt the registry either — the aliased-slice failure mode the internal
// packages already guard their own signature/key fields against.
func TestDirectoryKeyCopies(t *testing.T) {
	pub, _ := genKey(t)
	dir := newMemberDirectory(platform)

	// Register through a caller-owned buffer, then vandalize the buffer.
	callerBuf := append(ed25519.PublicKey(nil), pub...)
	acct, member := dir.register(callerBuf)
	callerBuf[0] ^= 0xFF

	got, ok := economyDirectory{dir}.PublicKey(acct)
	if !ok || !bytes.Equal(got, pub) {
		t.Fatal("mutating the caller's registered buffer corrupted the economy view of the directory")
	}
	got, ok = covenantDirectory{dir}.PublicKey(member)
	if !ok || !bytes.Equal(got, pub) {
		t.Fatal("mutating the caller's registered buffer corrupted the covenant view of the directory")
	}

	// Vandalize a returned key; a fresh lookup must be unaffected.
	got[0] ^= 0xFF
	again, ok := covenantDirectory{dir}.PublicKey(member)
	if !ok || !bytes.Equal(again, pub) {
		t.Fatal("mutating a returned key corrupted the registry (adapter returned an aliased slice)")
	}
	eGot, ok := economyDirectory{dir}.PublicKey(acct)
	if !ok || !bytes.Equal(eGot, pub) {
		t.Fatal("mutating a covenant-returned key corrupted the economy view (views alias one unprotected slice)")
	}
	eGot[0] ^= 0xFF
	again, ok = economyDirectory{dir}.PublicKey(acct)
	if !ok || !bytes.Equal(again, pub) {
		t.Fatal("mutating an economy-returned key corrupted the registry (adapter returned an aliased slice)")
	}
}

// TestAnchorsLogBinding pins the Anchors predicate's own log binding, added
// as defense in depth: an entry sealed for a FOREIGN log, smuggled into the
// operator's store out-of-band (bypassing Log.Append, which would refuse it)
// and even indexed, must not anchor — the predicate re-checks e.Log against
// the operator's LogID instead of trusting the store's contents.
func TestAnchorsLogBinding(t *testing.T) {
	alicePub, alicePriv := genKey(t)
	bobPub, bobPriv := genKey(t)
	operatorPub, _ := genKey(t)
	foreignOperatorPub, _ := genKey(t)
	_, stewardPriv := genKey(t)

	dir := newMemberDirectory(platform)
	_, aliceMember := dir.register(alicePub)
	_, bobMember := dir.register(bobPub)
	st := newStack(t, dir, operatorPub, []ed25519.PrivateKey{stewardPriv}, 1)

	// A perfectly valid, dual-sealed entry — but bound to someone else's log.
	foreign := sealEntry(t, record.LogID(foreignOperatorPub), alicePub, alicePriv, bobPub, bobPriv,
		record.HashContent([]byte("a covenant sealed for a foreign log")), time.Now().UTC())

	// Bypass the Log (which would reject the foreign binding) and write the
	// entry straight into the store, then index it as a buggy ingress would.
	if err := st.recStore.Append(foreign); err != nil {
		t.Fatalf("bypass-appending foreign-log entry to the raw store: %v", err)
	}
	n, err := st.recStore.Len()
	if err != nil {
		t.Fatalf("store len: %v", err)
	}
	st.anchors.noteAppended(foreign.ID(), n-1)

	if st.anchors.Sealed(covenant.ExchangeRef(foreign.ID()), aliceMember, bobMember) {
		t.Fatal("Anchors anchored a verified entry bound to a foreign log; the e.Log binding check is missing")
	}
}

// newDisputeRegistry builds a dispute.Registry over the stack's record log and
// index: the disputeAnchors twin shares the SAME Entry.ID()->seq index the
// covenant recordAnchors uses, so one index serves both cross-layer joins.
func newDisputeRegistry(t *testing.T, st *stack, adjudicators []ed25519.PublicKey, threshold int) *dispute.Registry {
	t.Helper()
	da := &disputeAnchors{store: st.recStore, logID: st.anchors.logID, index: st.anchors.index}
	reg, err := dispute.NewRegistry(
		dispute.Charter{Platform: platform, Adjudicators: adjudicators, Threshold: threshold},
		da, dispute.NewMemStore())
	if err != nil {
		t.Fatalf("dispute.NewRegistry: %v", err)
	}
	return reg
}

// sealArtifactIntoRecord mirrors an admitted dispute artifact into the
// operator's record log for tamper-evidence: the artifact's canonical bytes go
// into a member-local Locker, and only their HashContent enters the commons as
// the Content of a new dialog-sealed Entry between the two named parties. This
// is the JFA no-PII discipline: the narrative never touches the record, only
// its hash. Returns the appended entry.
func sealArtifactIntoRecord(t *testing.T, st *stack, artifactBytes []byte, pPub ed25519.PublicKey, pPriv ed25519.PrivateKey, aPub ed25519.PublicKey, aPriv ed25519.PrivateKey, at time.Time) record.Entry {
	t.Helper()
	locker := record.NewMemLocker()
	content := locker.Put(artifactBytes)
	if content != record.HashContent(artifactBytes) {
		t.Fatal("Locker.Put and HashContent disagree on the artifact hash")
	}
	e := sealEntry(t, st.anchors.logID, pPub, pPriv, aPub, aPriv, content, at)
	st.appendEntry(t, e)
	if e.Content != record.HashContent(artifactBytes) {
		t.Fatal("sealed entry Content is not the artifact hash")
	}
	return e
}

// TestDisputeDomainEndToEnd exercises the dispute domain seam end to end: the
// record.Hash <-> dispute.ExchangeRef conversion, the dispute.Anchors gate on
// Open, the economy.Mode -> dispute.Mode mapping, and the two mode-aware
// resolution paths — escrow escalation (moves no money) and credit
// (reputational overlay plus a VOLUNTARY refund that dispute can never force) —
// each with its artifact sealed into the record for tamper-evidence.
func TestDisputeDomainEndToEnd(t *testing.T) {
	t.Run("escrow escalation moves no money and seals into record", func(t *testing.T) {
		comPub, comPriv := genKey(t) // complainant
		resPub, resPriv := genKey(t) // respondent
		intakePub, intakePriv := genKey(t)
		adj1Pub, adj1 := genKey(t)
		adj2Pub, adj2 := genKey(t)
		operatorPub, operatorPriv := genKey(t)
		_, witnessPriv := genKey(t)
		_, stewardPriv := genKey(t)

		dir := newMemberDirectory(platform)
		comAcct, _ := dir.register(comPub)
		resAcct, _ := dir.register(resPub)
		st := newStack(t, dir, operatorPub, []ed25519.PrivateKey{stewardPriv}, 1)
		reg := newDisputeRegistry(t, st, []ed25519.PublicKey{adj1Pub, adj2Pub}, 2)

		// The disputed exchange: a sealed record entry between the two members.
		entry := sealEntry(t, st.anchors.logID, comPub, comPriv, resPub, resPriv,
			record.HashContent([]byte("com paid res for a service")), time.Now().UTC())
		st.appendEntry(t, entry)
		exRef := dispute.ExchangeRef(entry.ID())

		// The Anchors gate rejects a fabricated exchange (the [32]byte conversion
		// and the party/log binding both live at this seam).
		var fabricated dispute.ExchangeRef
		for i := range fabricated {
			fabricated[i] = 0xAB
		}
		badOpening, err := dispute.NewOpening(platform, comPub, resPub, fabricated, [32]byte{}, time.Now().UTC())
		if err != nil {
			t.Fatalf("NewOpening: %v", err)
		}
		if err := badOpening.Sign(comPriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := reg.Open(badOpening); !errors.Is(err, dispute.ErrInvalid) {
			t.Fatalf("Open(fabricated exchange) = %v, want ErrInvalid from the Anchors gate", err)
		}

		// Open the real dispute; the reason text stays member-local (only its
		// hash rides in the commons).
		reason := record.NewMemLocker()
		reasonHash := reason.Put([]byte("the deliverable never arrived"))
		opening, err := dispute.NewOpening(platform, comPub, resPub, exRef, [32]byte(reasonHash), time.Now().UTC())
		if err != nil {
			t.Fatalf("NewOpening: %v", err)
		}
		if err := opening.Sign(comPriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		id, err := reg.Open(opening)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		// Seal the opening into the record: complainant (proposer) + intake staff
		// (acceptor). The acceptor seal is acknowledgment/service, NOT consent.
		sealArtifactIntoRecord(t, st, opening.CanonicalBytes(), comPub, comPriv, intakePub, intakePriv, time.Now().UTC())

		// The seam maps the ledger's escrow mode onto the ruling.
		if got := disputeMode(t, st.ledger.Policy().Mode); got != dispute.ModeEscrow {
			t.Fatalf("mode mapping = %v, want ModeEscrow", got)
		}

		// A four-eyes escrow ruling: a staff-signed directive to the coordinator
		// with an OPAQUE Units quantity — no economy.Amount, no fiat.
		rationaleHash := record.HashContent([]byte("panel directs the coordinator to refund the complainant"))
		ruling := dispute.NewEscrowRuling(platform, id, exRef, dispute.FindingForComplainant,
			dispute.ActionRefundComplainant, 7, [32]byte(rationaleHash), time.Now().UTC())
		ruling.Sign(adj1)
		ruling.Sign(adj2)
		if err := reg.Rule(ruling); err != nil {
			t.Fatalf("Rule: %v", err)
		}

		// Cloudy structurally cannot move escrowed fiat: a credit spend is refused
		// and no balance moves — the ruling is a directive, not a settlement.
		spend := economy.Spend{Platform: platform, From: comAcct, To: resAcct, Amount: 1,
			ExchangeHash: [32]byte(entry.ID()), IssuedAt: time.Now().UTC(), Nonce: 1}
		spend.Sign(comPriv)
		if err := st.ledger.Post(spend); !errors.Is(err, economy.ErrCreditDisabled) {
			t.Fatalf("Post under escrow = %v, want ErrCreditDisabled", err)
		}
		if st.ledger.Balance(comAcct) != 0 || st.ledger.Balance(resAcct) != 0 {
			t.Fatal("escrow escalation moved credit; Cloudy must move no money in escrow mode")
		}

		// Seal the ruling into the record via two panel adjudicators (four-eyes),
		// then checkpoint and have an independent witness countersign.
		rulingEntry := sealArtifactIntoRecord(t, st, ruling.CanonicalBytes(), adj1Pub, adj1, adj2Pub, adj2, time.Now().UTC())
		cp := st.log.Checkpoint(time.Now().UTC())
		cp.Sign(operatorPriv)
		wit := record.NewWitness(witnessPriv)
		cs, err := wit.Countersign(cp, operatorPub, nil)
		if err != nil {
			t.Fatalf("witness countersign: %v", err)
		}
		wcp := record.WitnessedCheckpoint{Checkpoint: cp, Countersignatures: []record.Countersignature{cs}}
		if !wcp.Verify(operatorPub) {
			t.Fatal("witnessed checkpoint over the dispute trail does not verify")
		}
		if rulingEntry.Content != record.HashContent(ruling.CanonicalBytes()) {
			t.Fatal("ruling record entry does not commit to the ruling's canonical bytes")
		}

		// The case is resolved with the escalation directive intact.
		c, err := reg.Case(id)
		if err != nil {
			t.Fatalf("Case: %v", err)
		}
		if c.State() != dispute.StateResolved {
			t.Fatalf("state = %v, want StateResolved", c.State())
		}
		rem, ok := c.Remedy()
		if !ok || rem.Escalation == nil || rem.Escalation.Action != dispute.ActionRefundComplainant || rem.Escalation.Units != 7 {
			t.Fatalf("escrow remedy shape wrong: %+v", rem)
		}
	})

	t.Run("credit reputational overlay and voluntary refund, never forced clawback", func(t *testing.T) {
		comPub, comPriv := genKey(t) // complainant = original payer
		resPub, resPriv := genKey(t) // respondent = original payee
		adj1Pub, adj1 := genKey(t)
		adj2Pub, adj2 := genKey(t)
		operatorPub, _ := genKey(t)
		_, stewardPriv := genKey(t)

		dir := newMemberDirectory(platform)
		comAcct, _ := dir.register(comPub)
		resAcct, _ := dir.register(resPub)
		st := newStack(t, dir, operatorPub, []ed25519.PrivateKey{stewardPriv}, 1)
		st.enactCredit(t, 100, 1, time.Now().UTC())
		reg := newDisputeRegistry(t, st, []ed25519.PublicKey{adj1Pub, adj2Pub}, 2)

		// The disputed exchange: sealed entry plus the original credit spend
		// (complainant pays respondent 7).
		entry := sealEntry(t, st.anchors.logID, comPub, comPriv, resPub, resPriv,
			record.HashContent([]byte("com paid res 7 credit for a service")), time.Now().UTC())
		st.appendEntry(t, entry)
		orig := economy.Spend{Platform: platform, From: comAcct, To: resAcct, Amount: 7,
			ExchangeHash: [32]byte(entry.ID()), IssuedAt: time.Now().UTC(), Nonce: 1}
		orig.Sign(comPriv)
		if err := st.ledger.Post(orig); err != nil {
			t.Fatalf("Post original spend: %v", err)
		}
		if st.ledger.Balance(comAcct) != -7 || st.ledger.Balance(resAcct) != 7 {
			t.Fatalf("post-spend balances: com=%d res=%d, want -7/+7", st.ledger.Balance(comAcct), st.ledger.Balance(resAcct))
		}

		exRef := dispute.ExchangeRef(entry.ID())
		opening, err := dispute.NewOpening(platform, comPub, resPub, exRef, [32]byte{}, time.Now().UTC())
		if err != nil {
			t.Fatalf("NewOpening: %v", err)
		}
		if err := opening.Sign(comPriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		id, err := reg.Open(opening)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		// The seam maps the ledger's credit mode onto the ruling.
		if got := disputeMode(t, st.ledger.Policy().Mode); got != dispute.ModeCredit {
			t.Fatalf("mode mapping = %v, want ModeCredit", got)
		}

		// A credit ruling for the complainant: expunge the harm as an adjudicated
		// overlay (NOT a covenant deletion) and direct a voluntary refund of 7.
		ruling := dispute.NewCreditRuling(platform, id, exRef, dispute.FindingForComplainant,
			dispute.HarmExpunged, &dispute.RefundDirective{Units: 7}, [32]byte{}, time.Now().UTC())
		ruling.Sign(adj1)
		ruling.Sign(adj2)
		if err := reg.Rule(ruling); err != nil {
			t.Fatalf("Rule: %v", err)
		}
		c, err := reg.Case(id)
		if err != nil {
			t.Fatalf("Case: %v", err)
		}
		rem, ok := c.Remedy()
		if !ok || rem.Harm != dispute.HarmExpunged || rem.Refund == nil || rem.Refund.Units != 7 {
			t.Fatalf("credit remedy shape wrong: %+v", rem)
		}

		// The refund is a NEW payee-signed Spend (original payee res -> original
		// payer com), which the seam builds UNSIGNED. Direction is implied by the
		// Finding (for the complainant -> back to the complainant). Forced
		// clawback is impossible: the unsigned template is refused, and balances
		// do not move.
		refund := economy.Spend{Platform: platform, From: resAcct, To: comAcct,
			Amount: economy.Amount(rem.Refund.Units), ExchangeHash: [32]byte(entry.ID()),
			IssuedAt: time.Now().UTC(), Nonce: 1}
		if err := st.ledger.Post(refund); !errors.Is(err, economy.ErrSignature) {
			t.Fatalf("unsigned refund Post = %v, want ErrSignature (dispute cannot force a clawback)", err)
		}
		if st.ledger.Balance(comAcct) != -7 || st.ledger.Balance(resAcct) != 7 {
			t.Fatal("a failed forced refund moved balances")
		}

		// Only when the payee (respondent) signs VOLUNTARILY does the refund
		// settle.
		refund.Sign(resPriv)
		if err := st.ledger.Post(refund); err != nil {
			t.Fatalf("voluntary refund Post: %v", err)
		}
		if st.ledger.Balance(comAcct) != 0 || st.ledger.Balance(resAcct) != 0 {
			t.Fatalf("post-refund balances: com=%d res=%d, want 0/0", st.ledger.Balance(comAcct), st.ledger.Balance(resAcct))
		}
	})
}
