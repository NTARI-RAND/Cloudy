package relay_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/record"
	"github.com/NTARI-RAND/Cloudy/internal/relay"
	"github.com/NTARI-RAND/Cloudy/internal/witnesskit"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sealed(t *testing.T, logID record.Hash, aPub ed25519.PublicKey, aPriv ed25519.PrivateKey, bPub ed25519.PublicKey, bPriv ed25519.PrivateKey, n byte) record.Entry {
	t.Helper()
	e, err := record.NewEntry(logID, aPub, bPub, record.HashContent([]byte{n}), record.Hash{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Seal(aPriv); err != nil {
		t.Fatal(err)
	}
	if err := e.Seal(bPriv); err != nil {
		t.Fatal(err)
	}
	return e
}

func postJSON(t *testing.T, url string, v any) *http.Response {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestFederationDropsTheStandInLabel is the record layer's whole point run
// hermetically: an operator publishes checkpoints; two independent MEMBER
// witnesses (witnesskit workers) poll the relay, verify, refuse nothing
// honest, and countersign; the assembled bundle verifies with independence
// and the stand-in label drops. The relay decides nothing anywhere in the
// flow. "Federation is structurally cheap: an independent witness joins by
// appending a countersignature" — here are two, joining by exactly that.
func TestFederationDropsTheStandInLabel(t *testing.T) {
	opPub, opPriv := key(t)
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)

	// Operator side: a real dialog log with two sealed covenants.
	log, err := record.OpenLog(opPub, record.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(sealed(t, record.LogID(opPub), aPub, aPriv, bPub, bPriv, 1)); err != nil {
		t.Fatal(err)
	}

	rl := relay.New(nil)
	srv := httptest.NewServer(rl.Handler())
	defer srv.Close()

	publish := func(from uint64) record.Checkpoint {
		cp := log.Checkpoint(time.Now().UTC())
		cp.Sign(opPriv)
		proof, err := log.ProveConsistency(from)
		if err != nil {
			t.Fatal(err)
		}
		msg := witnesskit.EncodeCheckpoint(cp, opPub, "dialog", from, proof)
		resp := postJSON(t, srv.URL+"/v1/logs/"+msg.Log+"/checkpoints", msg)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("publish: %d", resp.StatusCode)
		}
		resp.Body.Close()
		return cp
	}
	cp1 := publish(0)

	// Two member witnesses join by running the boring worker.
	w1 := witnesskit.NewWorker(mustPriv(t), srv.URL)
	w2 := witnesskit.NewWorker(mustPriv(t), srv.URL)
	for _, w := range []*witnesskit.Worker{w1, w2} {
		n, err := w.RunOnce()
		if err != nil || n != 1 {
			t.Fatalf("RunOnce: n=%d err=%v", n, err)
		}
	}

	// The reader assembles the bundle and applies ITS OWN independence
	// checks — the relay handed over everything unranked.
	bundle := fetchBundle(t, srv.URL, hex.EncodeToString(cp1.Log[:]))
	wc := reconstruct(t, bundle)
	if !wc.Verify(opPub) {
		t.Fatal("federated bundle must verify")
	}
	if wc.StandIn(opPub) {
		t.Fatal("two independent member witnesses countersigned; the stand-in label must drop")
	}

	// The log grows; witnesses countersign the extension (their rollback
	// memory verifying consistency), and the new bundle federates too.
	if _, err := log.Append(sealed(t, record.LogID(opPub), aPub, aPriv, bPub, bPriv, 2)); err != nil {
		t.Fatal(err)
	}
	cp2 := publish(cp1.Size)
	for _, w := range []*witnesskit.Worker{w1, w2} {
		if n, err := w.RunOnce(); err != nil || n != 1 {
			t.Fatalf("RunOnce after extension: n=%d err=%v", n, err)
		}
	}
	bundle = fetchBundle(t, srv.URL, hex.EncodeToString(cp2.Log[:]))
	wc = reconstruct(t, bundle)
	if wc.Checkpoint.Size != 2 || !wc.Verify(opPub) || wc.StandIn(opPub) {
		t.Fatal("extended checkpoint must federate the same way")
	}

	// A rewriting operator is refused BY THE WITNESSES, not the relay: a
	// forked checkpoint at the same size, published to the relay (which
	// caches shape without judgment), gathers no honest countersignature.
	fork := cp2
	fork.Head[0] ^= 1
	fork.Sign(opPriv)
	forkMsg := witnesskit.EncodeCheckpoint(fork, opPub, "dialog", cp2.Size, nil)
	forkMsg.Size = cp2.Size + 1 // lie about growth so the relay caches it
	resp := postJSON(t, srv.URL+"/v1/logs/"+forkMsg.Log+"/checkpoints", forkMsg)
	resp.Body.Close()
	for _, w := range []*witnesskit.Worker{w1, w2} {
		if n, _ := w.RunOnce(); n != 0 {
			t.Fatal("a witness countersigned a fork; the one thing it exists to never do")
		}
	}
}

// TestFilingFanOut: the relay forwards the one witness write to every
// intake and returns receipts; each receipt verifies and is independent of
// the operator. A filer without a relay hits an intake directly — same
// result, proving the relay is convenience, not dependency.
func TestFilingFanOut(t *testing.T) {
	opPub, _ := key(t)
	filerPub, filerPriv := key(t)

	w1 := witnesskit.NewWorker(mustPriv(t), "")
	w2 := witnesskit.NewWorker(mustPriv(t), "")
	i1 := httptest.NewServer(w1.IntakeHandler())
	defer i1.Close()
	i2 := httptest.NewServer(w2.IntakeHandler())
	defer i2.Close()

	rl := relay.New([]string{i1.URL, i2.URL})
	srv := httptest.NewServer(rl.Handler())
	defer srv.Close()

	f := record.FilingCommitment{
		Claim:    record.HashContent([]byte("claim")),
		Exchange: record.HashContent([]byte("exchange")),
		TypeHash: record.HashContent([]byte("trade-harm")),
		At:       time.Now().UTC(),
		Filer:    filerPub,
	}
	f.Sign(filerPriv)
	msg := witnesskit.FilingMsg{
		Claim:     hex.EncodeToString(f.Claim[:]),
		Exchange:  hex.EncodeToString(f.Exchange[:]),
		TypeHash:  hex.EncodeToString(f.TypeHash[:]),
		At:        f.At.Format(time.RFC3339Nano),
		Filer:     hex.EncodeToString(filerPub),
		Signature: hex.EncodeToString(f.Signature),
	}

	resp := postJSON(t, srv.URL+"/v1/filings", msg)
	defer resp.Body.Close()
	var out struct {
		Receipts []witnesskit.ReceiptMsg `json:"receipts"`
		Intakes  int                     `json:"intakes"`
		Failures int                     `json:"failures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Intakes != 2 || out.Failures != 0 || len(out.Receipts) != 2 {
		t.Fatalf("fan-out: %+v", out)
	}
	seen := map[string]bool{}
	for _, r := range out.Receipts {
		receipt := reconstructReceipt(t, f, r)
		if !receipt.Verify() {
			t.Fatal("fan-out receipt must verify")
		}
		if !receipt.IndependentOf(opPub) {
			t.Fatal("member-witness receipts are independent of the operator")
		}
		seen[r.Witness] = true
	}
	if len(seen) != 2 {
		t.Fatal("receipts must come from two distinct witnesses")
	}

	// Direct-to-intake works without the relay.
	resp = postJSON(t, i1.URL+"/v1/filings", msg)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("a filer must be able to bypass the relay entirely")
	}
}

func mustPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func fetchBundle(t *testing.T, base, logID string) relay.BundleMsg {
	t.Helper()
	resp, err := http.Get(base + "/v1/logs/" + logID + "/checkpoints/latest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var bundle relay.BundleMsg
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func reconstruct(t *testing.T, bundle relay.BundleMsg) record.WitnessedCheckpoint {
	t.Helper()
	cp, _, _, _, err := witnesskit.DecodeCheckpoint(bundle.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	wc := record.WitnessedCheckpoint{Checkpoint: cp}
	for _, cs := range bundle.Countersignatures {
		wRaw, err := hex.DecodeString(cs.Witness)
		if err != nil {
			t.Fatal(err)
		}
		sRaw, err := hex.DecodeString(cs.Signature)
		if err != nil {
			t.Fatal(err)
		}
		wc.Countersignatures = append(wc.Countersignatures, record.Countersignature{
			Witness:   ed25519.PublicKey(wRaw),
			Signature: sRaw,
		})
	}
	return wc
}

func reconstructReceipt(t *testing.T, f record.FilingCommitment, r witnesskit.ReceiptMsg) record.FilingReceipt {
	t.Helper()
	wRaw, err := hex.DecodeString(r.Witness)
	if err != nil {
		t.Fatal(err)
	}
	sRaw, err := hex.DecodeString(r.Signature)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, r.ReceivedAt)
	if err != nil {
		t.Fatal(err)
	}
	return record.FilingReceipt{
		Commitment: f,
		Witness:    ed25519.PublicKey(wRaw),
		ReceivedAt: at.UTC(),
		Signature:  sRaw,
	}
}
