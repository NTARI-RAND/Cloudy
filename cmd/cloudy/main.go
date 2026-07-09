// Command cloudy is the entrypoint for the Cloudy frontend and its runtime
// composition root: the one place at runtime where the three JFA
// member-economy layers (economy, covenant, record — which never import each
// other) are constructed together, over one shared member directory, alongside
// the coordinator client. test/composition proves the same composition end to
// end.
//
// Startup is honest about what it is: keys are ephemeral, stores are
// in-memory, the member directory is empty, and there is still no live
// coordination loop and no member-facing surface. The steward private key is
// discarded at startup, so no quorum PolicyChange — and therefore no
// escrow->credit transition — is reachable in this process. Construction
// proves the layers compose; nothing serves members yet.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"log"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/coord"
	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/dispute"
	"github.com/NTARI-RAND/Cloudy/internal/economy"
	"github.com/NTARI-RAND/Cloudy/internal/record"
)

// memberDirectory is the single shared member directory backing all three
// layers: a member's economy AccountID, covenant MemberID, and record-layer
// public key all answer to the same keypair registered here. No JFA package
// stores or derives keys for another; each resolves keys out-of-band through
// a typed view. It is empty at startup — member registration has no ingress
// yet, and register below is the only path an ingress may use.
type memberDirectory struct {
	platform  string
	byAccount map[economy.AccountID]ed25519.PublicKey
	byMember  map[covenant.MemberID]ed25519.PublicKey
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
// registry (Go method sets cannot overload PublicKey by ID type). Every
// adapter returns a COPY of the registered key, so no caller can corrupt the
// registry through a returned slice.
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

// recordAnchors implements covenant.Anchors against the operator's record
// log: resolve both MemberIDs through the shared directory, find the entry
// whose ID() equals the ExchangeRef (the root keeps its own ID->seq index,
// maintained by operatorLog.appendEntry below; record exports none by
// design), and demand an entry bound to THIS operator log (e.Log == logID —
// defense in depth against a bypass-written or hostile store; Log.Append
// already refuses foreign-log entries) that fully verifies and is sealed by
// exactly the resolved pair, in either order.
type recordAnchors struct {
	dir   *memberDirectory
	store record.Store
	logID record.Hash            // LogID of the one operator log entries may anchor to
	index map[record.Hash]uint64 // Entry.ID() -> sequence in the operator's log
}

// noteAppended maintains the root's ID->seq index; operatorLog.appendEntry is
// the only caller.
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

// disputeAnchors implements dispute.Anchors, the dispute-side twin of
// recordAnchors: the same join to the operator's record log on Entry.ID(), but
// the dispute port speaks raw ed25519 public keys (not covenant MemberIDs), so
// the party match compares the resolved keys directly. It REUSES the root's
// one Entry.ID()->seq index (the same map recordAnchors holds), so a single
// index serves both cross-layer joins; the [32]byte conversion between
// record.Hash and dispute.ExchangeRef happens here and nowhere else.
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

// operatorLog couples the operator's record.Log with the anchors index.
// appendEntry is the ONLY append path any ingress may use: calling
// record.Log.Append directly would persist the entry without indexing it,
// leaving every assessment of that exchange unanchorable forever.
type operatorLog struct {
	log     *record.Log
	anchors *recordAnchors
}

// appendEntry appends e to the operator log and records its ID->seq mapping
// in the root's index so covenant assessments can anchor to it.
func (o *operatorLog) appendEntry(e record.Entry) (uint64, error) {
	seq, err := o.log.Append(e)
	if err != nil {
		return 0, err
	}
	o.anchors.noteAppended(e.ID(), seq)
	return seq, nil
}

func main() {
	addr := flag.String("coordinator", "http://localhost:8080", "base URL of the sohocloud coordinator")
	flag.Parse()

	const platform = "cloudy"

	// Ephemeral keys and in-memory stores: this process is not yet a durable
	// deployment and does not pretend to be one. The steward PRIVATE key is
	// deliberately discarded — nothing in this process can sign a
	// PolicyChange, so the ledger cannot leave escrow while it runs.
	operatorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("cloudy: generating ephemeral operator key: %v", err)
	}
	stewardPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("cloudy: generating ephemeral steward key: %v", err)
	}

	dir := &memberDirectory{
		platform:  platform,
		byAccount: make(map[economy.AccountID]ed25519.PublicKey),
		byMember:  make(map[covenant.MemberID]ed25519.PublicKey),
	}

	recStore := record.NewMemStore()
	opLog, err := record.OpenLog(operatorPub, recStore)
	if err != nil {
		log.Fatalf("cloudy: opening operator record log: %v", err)
	}

	ledger, err := economy.Open(economy.Genesis{
		Platform:  platform,
		Stewards:  []ed25519.PublicKey{stewardPub},
		Threshold: 1,
		Policy:    economy.Policy{Mode: economy.ModeEscrow},
	}, economyDirectory{dir}, economy.NewMemStore())
	if err != nil {
		log.Fatalf("cloudy: opening economy ledger: %v", err)
	}

	anchors := &recordAnchors{
		dir:   dir,
		store: recStore,
		logID: record.LogID(operatorPub),
		index: make(map[record.Hash]uint64),
	}
	ops := &operatorLog{log: opLog, anchors: anchors}
	_ = ops // the ingress's ONLY append path; there is no ingress yet

	// The platform string handed to NewBook is the SAME platform the economy
	// Genesis is scoped to and the same one register mints IDs under — Record
	// re-derives every MemberID from the directory key under it. The nil
	// categories slice takes the LBTAS default closed vocabulary:
	// reliability, usability, performance, support.
	book, err := covenant.NewBook(platform, nil, covenantDirectory{dir}, anchors, covenant.NewMemStore())
	if err != nil {
		log.Fatalf("cloudy: opening covenant book: %v", err)
	}
	_ = book // constructed and live; assessments have no ingress until members exist

	// The dispute registry composes the fourth JFA leaf over the same operator
	// log: its Anchors twin shares the one Entry.ID()->seq index, so disputes
	// gate on the same sealed exchanges. The adjudicator PRIVATE key is
	// discarded like the steward's — no ruling is signable in this process — and
	// a single-adjudicator charter cannot dialog-seal rulings into the record
	// (that path wants Threshold>=2), so tamper-evidence here is the registry's
	// own append-only Store until a real staff panel exists.
	adjudicatorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("cloudy: generating ephemeral adjudicator key: %v", err)
	}
	dispAnchors := &disputeAnchors{store: recStore, logID: record.LogID(operatorPub), index: anchors.index}
	registry, err := dispute.NewRegistry(dispute.Charter{
		Platform:     platform,
		Adjudicators: []ed25519.PublicKey{adjudicatorPub},
		Threshold:    1,
	}, dispAnchors, dispute.NewMemStore())
	if err != nil {
		log.Fatalf("cloudy: opening dispute registry: %v", err)
	}
	_ = registry // constructed and live; disputes have no ingress until members exist

	c := coord.Dial(*addr)
	_ = c // constructed and deliberately unused: there is still no live loop

	log.Printf("cloudy: record: operator log open at size %d (in-memory store, ephemeral operator key)",
		opLog.Checkpoint(time.Now().UTC()).Size)
	log.Printf("cloudy: economy: ledger open at ModeEscrow genesis (platform %q, mode %q); the steward private key was discarded at startup, so no quorum PolicyChange — and no escrow->credit transition — is reachable in this process",
		platform, ledger.Policy().Mode)
	log.Printf("cloudy: covenant: book open over the shared member directory with record-anchored admission on the LBTAS scale (six levels, -1 No Trust .. +4 Delight; default categories reliability, usability, performance, support; standing read as distributions, never averaged; directory empty; no assessment ingress yet)")
	log.Printf("cloudy: dispute: registry open over the same operator log with record-anchored Open admission (generic adjudicator charter, threshold 1; escrow rulings escalate to the coordinator and move no money, credit rulings carry a reputational overlay and only a voluntary refund directive — never a forced clawback; the adjudicator private key was discarded, so no ruling is signable and no dispute ingress exists yet)")
	log.Printf("cloudy: coordinator client constructed for %s; no live coordination loop and no member-facing surface yet", *addr)
}
