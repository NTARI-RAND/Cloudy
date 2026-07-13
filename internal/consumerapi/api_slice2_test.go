package consumerapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/dispute"
	"github.com/NTARI-RAND/Cloudy/internal/economy"
	"github.com/NTARI-RAND/Cloudy/internal/record"
)

// sealExchange drives the full client-side dialog-seal flow over the API:
// fetch the operator's log identity, build the entry, seal it with BOTH
// member keys locally (keys never touch the server), and post it. It returns
// the leaf ID hex — THE cross-layer exchange reference.
func sealExchange(t *testing.T, h http.Handler, pubA ed25519.PublicKey, privA ed25519.PrivateKey, pubB ed25519.PublicKey, privB ed25519.PrivateKey) string {
	t.Helper()
	rec, body := do(t, h, "GET", "/api/v1/drops/log", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("drops/log: code %d body %s", rec.Code, rec.Body.String())
	}
	logHex, _ := body["log_id"].(string)
	logRaw, err := hex.DecodeString(logHex)
	if err != nil || len(logRaw) != 32 {
		t.Fatalf("drops/log returned unusable log_id %q", logHex)
	}
	var logID record.Hash
	copy(logID[:], logRaw)

	e, err := record.NewEntry(logID, pubA, pubB, record.HashContent([]byte("member-local narrative")), record.Hash{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Seal(privA); err != nil {
		t.Fatal(err)
	}
	if err := e.Seal(privB); err != nil {
		t.Fatal(err)
	}
	rec, body = do(t, h, "POST", "/api/v1/drops", dropRequest{
		Log:          logHex,
		Proposer:     hex.EncodeToString(pubA),
		Acceptor:     hex.EncodeToString(pubB),
		Content:      hex.EncodeToString(e.Content[:]),
		Nonce:        hex.EncodeToString(e.Nonce[:]),
		SealedAt:     e.SealedAt.Format(time.RFC3339Nano),
		ProposerSeal: hex.EncodeToString(e.ProposerSeal),
		AcceptorSeal: hex.EncodeToString(e.AcceptorSeal),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST drops: code %d body %s", rec.Code, rec.Body.String())
	}
	id, _ := body["id"].(string)
	want := e.ID()
	if id != hex.EncodeToString(want[:]) {
		t.Fatalf("POST drops returned id %q, want the entry's leaf ID %q", id, hex.EncodeToString(want[:]))
	}
	return id
}

func TestDropsAppendReadAndStandInLabel(t *testing.T) {
	h := newTestServer(t)
	pubA, privA := key(1)
	pubB, privB := key(2)
	registerMember(t, h, pubA, privA)
	registerMember(t, h, pubB, privB)

	id := sealExchange(t, h, pubA, privA, pubB, privB)

	rec, body := do(t, h, "GET", "/api/v1/drops/"+id, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET drop: code %d body %s", rec.Code, rec.Body.String())
	}
	if body["proposer"] != hex.EncodeToString(pubA) || body["acceptor"] != hex.EncodeToString(pubB) {
		t.Fatalf("GET drop returned wrong parties: %v", body)
	}
	if _, hasCorrects := body["corrects"]; hasCorrects {
		t.Fatalf("plain covenant must omit corrects, got %v", body["corrects"])
	}

	// The checkpoint MUST carry the honest single-witness stand-in label, and
	// its signature must verify under the operator key the API itself serves.
	rec, body = do(t, h, "GET", "/api/v1/drops/checkpoints", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET checkpoints: code %d", rec.Code)
	}
	if body["stand_in"] != true {
		t.Fatal("zero-witness deployment did not label itself a stand-in; misrepresenting federation is forbidden")
	}
	if body["size"].(float64) != 1 {
		t.Fatalf("checkpoint size = %v, want 1", body["size"])
	}
	_, lg := do(t, h, "GET", "/api/v1/drops/log", nil)
	opKey, err := hex.DecodeString(lg["operator_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var cp record.Checkpoint
	logRaw, _ := hex.DecodeString(body["log"].(string))
	headRaw, _ := hex.DecodeString(body["head"].(string))
	copy(cp.Log[:], logRaw)
	copy(cp.Head[:], headRaw)
	cp.Size = uint64(body["size"].(float64))
	cp.IssuedAt, err = time.Parse(time.RFC3339Nano, body["issued_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	cp.Signature, _ = hex.DecodeString(body["signature"].(string))
	if !cp.Verify(ed25519.PublicKey(opKey)) {
		t.Fatal("served checkpoint does not verify under the served operator key")
	}

	// Unregistered parties cannot enter the log through this ingress.
	pubC, privC := key(3)
	e, err := record.NewEntry(cp.Log, pubA, pubC, record.HashContent([]byte("n")), record.Hash{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_ = e.Seal(privA)
	_ = e.Seal(privC)
	rec, _ = do(t, h, "POST", "/api/v1/drops", dropRequest{
		Log:          hex.EncodeToString(cp.Log[:]),
		Proposer:     hex.EncodeToString(pubA),
		Acceptor:     hex.EncodeToString(pubC),
		Content:      hex.EncodeToString(e.Content[:]),
		Nonce:        hex.EncodeToString(e.Nonce[:]),
		SealedAt:     e.SealedAt.Format(time.RFC3339Nano),
		ProposerSeal: hex.EncodeToString(e.ProposerSeal),
		AcceptorSeal: hex.EncodeToString(e.AcceptorSeal),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unregistered acceptor: code %d, want 400", rec.Code)
	}
}

func TestAssessmentsAnchorToSealedDialogs(t *testing.T) {
	h := newTestServer(t)
	pubA, privA := key(1)
	pubB, privB := key(2)
	registerMember(t, h, pubA, privA)
	registerMember(t, h, pubB, privB)
	id := sealExchange(t, h, pubA, privA, pubB, privB)

	assess := func(exchangeHex string, level int8, commentHash string) (*int, string) {
		exRaw, _ := hex.DecodeString(exchangeHex)
		var ex covenant.ExchangeRef
		copy(ex[:], exRaw)
		a := covenant.Assessment{
			Assessor: covenant.MemberIDFor(platform, pubA),
			Subject:  covenant.MemberIDFor(platform, pubB),
			Exchange: ex,
			Relation: covenant.RelationTrade,
			Category: "reliability",
			Level:    covenant.Level(level),
			IssuedAt: time.Now().UTC(),
		}
		if commentHash != "" {
			raw, _ := hex.DecodeString(commentHash)
			copy(a.CommentHash[:], raw)
		}
		a.Sign(privA)
		rec, body := do(t, h, "POST", "/api/v1/assessments", assessmentRequest{
			Assessor:    string(a.Assessor),
			Subject:     string(a.Subject),
			Exchange:    exchangeHex,
			Relation:    string(a.Relation),
			Category:    a.Category,
			Level:       level,
			CommentHash: commentHash,
			IssuedAt:    a.IssuedAt.Format(time.RFC3339Nano),
			Signature:   hex.EncodeToString(a.Signature),
		})
		errMsg, _ := body["error"].(string)
		return &rec.Code, errMsg
	}

	if code, msg := assess(id, 3, ""); *code != http.StatusOK {
		t.Fatalf("anchored assessment refused: %d %s", *code, msg)
	}
	// The same assessor re-assessing the same exchange under the same
	// category is a duplicate, reported as a conflict.
	if code, _ := assess(id, 2, ""); *code != http.StatusConflict {
		t.Fatalf("duplicate assessment: code %d, want 409", *code)
	}
	// An exchange that never sealed anchors nothing.
	fake := sha256.Sum256([]byte("no such exchange"))
	if code, _ := assess(hex.EncodeToString(fake[:]), 3, ""); *code != http.StatusBadRequest {
		t.Fatalf("unanchored assessment: code %d, want 400", *code)
	}

	// Standing serves distributions and the harm count — never an average.
	rec, body := do(t, h, "GET", "/api/v1/members/"+string(covenant.MemberIDFor(platform, pubB))+"/standing", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("standing: code %d", rec.Code)
	}
	relations := body["relations"].(map[string]any)
	trade := relations["trade"].(map[string]any)
	overall := trade["overall"].(map[string]any)
	if overall["total"].(float64) != 1 {
		t.Fatalf("trade standing total = %v, want 1", overall["total"])
	}
	counts := overall["counts"].(map[string]any)
	if counts[covenant.Level(3).String()].(float64) != 1 {
		t.Fatalf("standing counts = %v, want one at %q", counts, covenant.Level(3).String())
	}
	// The response is typed by relation and carries NO cross-relation pool
	// and no scalar summary anywhere.
	for _, rel := range []string{"trade", "adjudication-conduct", "verdict-satisfaction"} {
		if _, ok := relations[rel]; !ok {
			t.Fatalf("standing response missing relation %q", rel)
		}
	}
	for k := range body {
		if k == "overall" || k == "average" || k == "score" || k == "rating" {
			t.Fatalf("standing response leaked a cross-relation or scalar field %q", k)
		}
	}
}

func TestSpendsRefusedWhileEscrow(t *testing.T) {
	h := newTestServer(t)
	pubA, privA := key(1)
	pubB, privB := key(2)
	registerMember(t, h, pubA, privA)
	registerMember(t, h, pubB, privB)
	id := sealExchange(t, h, pubA, privA, pubB, privB)

	rec, body := do(t, h, "GET", "/api/v1/credit/policy", nil)
	if rec.Code != http.StatusOK || body["mode"] != "escrow" {
		t.Fatalf("policy: code %d body %v, want escrow mode", rec.Code, body)
	}

	exRaw, _ := hex.DecodeString(id)
	var ex [32]byte
	copy(ex[:], exRaw)
	sp := economy.Spend{
		Platform:     platform,
		From:         economy.AccountIDFor(platform, pubA),
		To:           economy.AccountIDFor(platform, pubB),
		Amount:       5,
		ExchangeHash: ex,
		IssuedAt:     time.Now().UTC(),
		Nonce:        1,
	}
	sp.Sign(privA)
	rec, body = do(t, h, "POST", "/api/v1/credit/spends", spendRequest{
		From:         hex.EncodeToString(sp.From[:]),
		To:           hex.EncodeToString(sp.To[:]),
		Amount:       uint64(sp.Amount),
		ExchangeHash: id,
		IssuedAt:     sp.IssuedAt.Format(time.RFC3339Nano),
		Nonce:        sp.Nonce,
		Signature:    hex.EncodeToString(sp.Signature),
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("spend in escrow mode: code %d body %v, want 409 — the escrow wall must hold", rec.Code, body)
	}

	// Balances and history stay a deterministic function of the (empty) sealed
	// spend record.
	acctA := hex.EncodeToString(sp.From[:])
	rec, body = do(t, h, "GET", "/api/v1/credit/accounts/"+acctA+"/balance", nil)
	if rec.Code != http.StatusOK || body["balance"].(float64) != 0 {
		t.Fatalf("balance: code %d body %v, want 0", rec.Code, body)
	}
	rec, body = do(t, h, "GET", "/api/v1/credit/accounts/"+acctA+"/history", nil)
	if rec.Code != http.StatusOK || len(body["spends"].([]any)) != 0 {
		t.Fatalf("history: code %d body %v, want no spends", rec.Code, body)
	}
}

func TestDisputeFileWithdrawLifecycle(t *testing.T) {
	h := newTestServer(t)
	pubA, privA := key(1)
	pubB, privB := key(2)
	registerMember(t, h, pubA, privA)
	registerMember(t, h, pubB, privB)
	id := sealExchange(t, h, pubA, privA, pubB, privB)

	exRaw, _ := hex.DecodeString(id)
	var ex dispute.ExchangeRef
	copy(ex[:], exRaw)
	reason := sha256.Sum256([]byte("member-local grievance narrative"))
	o, err := dispute.NewOpening(platform, pubA, pubB, ex, reason, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Sign(privA); err != nil {
		t.Fatal(err)
	}
	// The filing commitment is signed CLIENT-side over the claim the opening
	// will create, and lodged at the intake before the registry acts.
	wantID := o.ID()
	typeHash := sha256.Sum256([]byte("trade-harm"))
	commitment := record.FilingCommitment{
		Claim:    record.Hash(wantID),
		Exchange: record.Hash(ex),
		TypeHash: record.Hash(typeHash),
		At:       o.OpenedAt,
		Filer:    pubA,
	}
	commitment.Sign(privA)
	req := openDisputeRequest{
		Complainant: hex.EncodeToString(pubA),
		Respondent:  hex.EncodeToString(pubB),
		Exchange:    id,
		ReasonHash:  hex.EncodeToString(o.ReasonHash[:]),
		Nonce:       hex.EncodeToString(o.Nonce[:]),
		OpenedAt:    o.OpenedAt.Format(time.RFC3339Nano),
		Signature:   hex.EncodeToString(o.Signature),
	}
	req.Filing.TypeHash = hex.EncodeToString(typeHash[:])
	req.Filing.At = o.OpenedAt.Format(time.RFC3339Nano)
	req.Filing.Signature = hex.EncodeToString(commitment.Signature)
	rec, body := do(t, h, "POST", "/api/v1/disputes", req)
	if rec.Code != http.StatusOK {
		t.Fatalf("open dispute: code %d body %s", rec.Code, rec.Body.String())
	}
	dID, _ := body["dispute_id"].(string)
	if dID != hex.EncodeToString(wantID[:]) {
		t.Fatalf("dispute_id %q, want Opening.ID() %q", dID, hex.EncodeToString(wantID[:]))
	}
	// The receipt is present and HONESTLY labeled: the intake runs in the
	// operator's process, so it must say independent=false.
	receipt, _ := body["filing_receipt"].(map[string]any)
	if receipt == nil {
		t.Fatal("open dispute must return the filing receipt")
	}
	if receipt["independent"] != false {
		t.Fatal("an operator-run intake must label its receipts non-independent")
	}

	// The lifecycle log shows the claim filed, as it happened.
	rec, body = do(t, h, "GET", "/api/v1/lifecycle/claims/"+dID, nil)
	if rec.Code != http.StatusOK || body["state"] != "filed" {
		t.Fatalf("lifecycle claim after open: code %d state %v, want filed", rec.Code, body["state"])
	}

	rec, body = do(t, h, "GET", "/api/v1/disputes/"+dID, nil)
	if rec.Code != http.StatusOK || body["state"] != "open" {
		t.Fatalf("case: code %d state %v, want open", rec.Code, body["state"])
	}

	// Only the complainant can withdraw: the respondent's signature is refused.
	wd := dispute.Withdrawal{Platform: platform, Dispute: dispute.DisputeID(wantID), WithdrawnAt: time.Now().UTC()}
	wd.Sign(privB)
	rec, _ = do(t, h, "POST", "/api/v1/disputes/"+dID+"/withdraw", withdrawRequest{
		WithdrawnAt: wd.WithdrawnAt.Format(time.RFC3339Nano),
		Signature:   hex.EncodeToString(wd.Signature),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("respondent withdrawal: code %d, want 400", rec.Code)
	}

	wd.Sign(privA)
	rec, _ = do(t, h, "POST", "/api/v1/disputes/"+dID+"/withdraw", withdrawRequest{
		WithdrawnAt: wd.WithdrawnAt.Format(time.RFC3339Nano),
		Signature:   hex.EncodeToString(wd.Signature),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("complainant withdrawal: code %d body %s", rec.Code, rec.Body.String())
	}
	rec, body = do(t, h, "GET", "/api/v1/disputes/"+dID, nil)
	if rec.Code != http.StatusOK || body["state"] != "withdrawn" {
		t.Fatalf("case after withdrawal: code %d state %v, want withdrawn", rec.Code, body["state"])
	}

	// The lifecycle log recorded the resolution as its own transition, and
	// the lifecycle checkpoint (stand-in labeled) covers both transitions.
	rec, body = do(t, h, "GET", "/api/v1/lifecycle/claims/"+dID, nil)
	if rec.Code != http.StatusOK || body["state"] != "resolved" {
		t.Fatalf("lifecycle claim after withdrawal: code %d state %v, want resolved", rec.Code, body["state"])
	}
	if n := len(body["transitions"].([]any)); n != 2 {
		t.Fatalf("lifecycle transitions = %d, want 2 (filed, resolved)", n)
	}
	rec, body = do(t, h, "GET", "/api/v1/lifecycle/checkpoints", nil)
	if rec.Code != http.StatusOK || body["stand_in"] != true || body["size"].(float64) != 2 {
		t.Fatalf("lifecycle checkpoint: code %d body %v, want stand_in=true size=2", rec.Code, body)
	}

	unknown := sha256.Sum256([]byte("no such case"))
	rec, _ = do(t, h, "GET", "/api/v1/disputes/"+hex.EncodeToString(unknown[:]), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown dispute: code %d, want 404", rec.Code)
	}
}

// TestDropProofVerifiesOffline drives the full member-verification story:
// seal a dialog, fetch its proof and checkpoint, and verify inclusion with
// nothing but the record package's public verifier — no operator trust.
func TestDropProofVerifiesOffline(t *testing.T) {
	h := newTestServer(t)
	pubA, privA := key(1)
	pubB, privB := key(2)
	registerMember(t, h, pubA, privA)
	registerMember(t, h, pubB, privB)

	// Seal via the API, keeping the client-side entry for verification.
	rec, body := do(t, h, "GET", "/api/v1/drops/log", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("drops/log: %d", rec.Code)
	}
	logRaw, _ := hex.DecodeString(body["log_id"].(string))
	opKeyRaw, _ := hex.DecodeString(body["operator_key"].(string))
	var logID record.Hash
	copy(logID[:], logRaw)
	e, err := record.NewEntry(logID, pubA, pubB, record.HashContent([]byte("n")), record.Hash{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_ = e.Seal(privA)
	_ = e.Seal(privB)
	rec, body = do(t, h, "POST", "/api/v1/drops", dropRequest{
		Log:          body["log_id"].(string),
		Proposer:     hex.EncodeToString(pubA),
		Acceptor:     hex.EncodeToString(pubB),
		Content:      hex.EncodeToString(e.Content[:]),
		Nonce:        hex.EncodeToString(e.Nonce[:]),
		SealedAt:     e.SealedAt.Format(time.RFC3339Nano),
		ProposerSeal: hex.EncodeToString(e.ProposerSeal),
		AcceptorSeal: hex.EncodeToString(e.AcceptorSeal),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST drops: %d %s", rec.Code, rec.Body.String())
	}
	id := body["id"].(string)

	rec, body = do(t, h, "GET", "/api/v1/drops/"+id+"/proof", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("proof: %d %s", rec.Code, rec.Body.String())
	}
	var p record.Proof
	p.Seq = uint64(body["seq"].(float64))
	for _, hstr := range body["path"].([]any) {
		raw, _ := hex.DecodeString(hstr.(string))
		var hh record.Hash
		copy(hh[:], raw)
		p.Path = append(p.Path, hh)
	}
	cpBody := body["checkpoint"].(map[string]any)
	var cp record.Checkpoint
	lr, _ := hex.DecodeString(cpBody["log"].(string))
	hr, _ := hex.DecodeString(cpBody["head"].(string))
	copy(cp.Log[:], lr)
	copy(cp.Head[:], hr)
	cp.Size = uint64(cpBody["size"].(float64))
	cp.IssuedAt, err = time.Parse(time.RFC3339Nano, cpBody["issued_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	cp.Signature, _ = hex.DecodeString(cpBody["signature"].(string))

	if !record.VerifyInclusion(e, p, cp, ed25519.PublicKey(opKeyRaw)) {
		t.Fatal("the served proof must verify offline against the served checkpoint and operator key")
	}
	// And the tamper story holds end to end.
	bad := e
	bad.Content[0] ^= 1
	if record.VerifyInclusion(bad, p, cp, ed25519.PublicKey(opKeyRaw)) {
		t.Fatal("a tampered entry must not verify")
	}
}

// TestConductRatingAndAdjudicatorAnswer drives the symmetry loop end to end
// over the API: a member with a real filed claim rates the operator's
// adjudication conduct No Trust; the operator — a member of its own platform
// — answers. The rating stays visible in its own typed stream; the answer
// annotates without erasing anything.
func TestConductRatingAndAdjudicatorAnswer(t *testing.T) {
	s, err := NewServer(platform)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	pubA, privA := key(1)
	pubB, privB := key(2)
	registerMember(t, h, pubA, privA)
	registerMember(t, h, pubB, privB)
	id := sealExchange(t, h, pubA, privA, pubB, privB)

	// File a real claim (the adjudication-relation anchor).
	exRaw, _ := hex.DecodeString(id)
	var ex dispute.ExchangeRef
	copy(ex[:], exRaw)
	reason := sha256.Sum256([]byte("grievance"))
	o, err := dispute.NewOpening(platform, pubA, pubB, ex, reason, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Sign(privA); err != nil {
		t.Fatal(err)
	}
	oid := o.ID()
	typeHash := sha256.Sum256([]byte("trade-harm"))
	commitment := record.FilingCommitment{
		Claim:    record.Hash(oid),
		Exchange: record.Hash(ex),
		TypeHash: record.Hash(typeHash),
		At:       o.OpenedAt,
		Filer:    pubA,
	}
	commitment.Sign(privA)
	req := openDisputeRequest{
		Complainant: hex.EncodeToString(pubA),
		Respondent:  hex.EncodeToString(pubB),
		Exchange:    id,
		ReasonHash:  hex.EncodeToString(o.ReasonHash[:]),
		Nonce:       hex.EncodeToString(o.Nonce[:]),
		OpenedAt:    o.OpenedAt.Format(time.RFC3339Nano),
		Signature:   hex.EncodeToString(o.Signature),
	}
	req.Filing.TypeHash = hex.EncodeToString(typeHash[:])
	req.Filing.At = o.OpenedAt.Format(time.RFC3339Nano)
	req.Filing.Signature = hex.EncodeToString(commitment.Signature)
	rec, _ := do(t, h, "POST", "/api/v1/disputes", req)
	if rec.Code != http.StatusOK {
		t.Fatalf("open dispute: %d %s", rec.Code, rec.Body.String())
	}

	// The complainant rates the OPERATOR's conduct: No Trust, with the
	// mandatory comment digest. The operator's member id is the subject.
	operatorMember := s.operatorMember
	commentDigest := sha256.Sum256([]byte("sat on my claim"))
	a := covenant.Assessment{
		Assessor:    covenant.MemberIDFor(platform, pubA),
		Subject:     operatorMember,
		Exchange:    covenant.ExchangeRef(record.Hash(ex)),
		Relation:    covenant.RelationAdjudicationConduct,
		Category:    "support",
		Level:       covenant.LevelNoTrust,
		CommentHash: commentDigest,
		IssuedAt:    time.Now().UTC(),
	}
	a.Sign(privA)
	rec, body := do(t, h, "POST", "/api/v1/assessments", assessmentRequest{
		Assessor:    string(a.Assessor),
		Subject:     string(a.Subject),
		Exchange:    id,
		Relation:    string(a.Relation),
		Category:    a.Category,
		Level:       int8(a.Level),
		CommentHash: hex.EncodeToString(commentDigest[:]),
		IssuedAt:    a.IssuedAt.Format(time.RFC3339Nano),
		Signature:   hex.EncodeToString(a.Signature),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("conduct assessment: %d %s", rec.Code, rec.Body.String())
	}
	assessmentID := body["id"].(string)

	// A member with NO claim on the exchange cannot rate conduct (Sybil
	// posture: the governance-relevant stream is not inflatable). The
	// respondent could — they are a genuine party — so the negative case is
	// a THIRD member who never touched the claim.
	pubC, privC := key(3)
	registerMember(t, h, pubC, privC)
	b := covenant.Assessment{
		Assessor: covenant.MemberIDFor(platform, pubC),
		Subject:  operatorMember,
		Exchange: covenant.ExchangeRef(record.Hash(ex)),
		Relation: covenant.RelationAdjudicationConduct,
		Category: "support",
		Level:    covenant.LevelBasicPromise,
		IssuedAt: time.Now().UTC(),
	}
	b.Sign(privC)
	rec, _ = do(t, h, "POST", "/api/v1/assessments", assessmentRequest{
		Assessor:  string(b.Assessor),
		Subject:   string(b.Subject),
		Exchange:  id,
		Relation:  string(b.Relation),
		Category:  b.Category,
		Level:     int8(b.Level),
		IssuedAt:  b.IssuedAt.Format(time.RFC3339Nano),
		Signature: hex.EncodeToString(b.Signature),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a stranger's conduct rating must be refused (got %d) — this stream is Sybil food otherwise", rec.Code)
	}

	// The operator answers through the same public surface — the recourse
	// the architecture demanded. It signs with its own key client-side; the
	// test reaches into the server only for the key, exactly like a real
	// operator would hold its own.
	answerDigest := sha256.Sum256([]byte("adjudication timeline, member-local"))
	an := covenant.Answer{
		Answerer:   operatorMember,
		AnswerHash: answerDigest,
		IssuedAt:   time.Now().UTC(),
	}
	idRaw, _ := hex.DecodeString(assessmentID)
	copy(an.Assessment[:], idRaw)
	an.Sign(s.operatorPriv)
	rec, _ = do(t, h, "POST", "/api/v1/assessments/"+assessmentID+"/answers", answerRequest{
		Answerer:   string(operatorMember),
		AnswerHash: hex.EncodeToString(answerDigest[:]),
		IssuedAt:   an.IssuedAt.Format(time.RFC3339Nano),
		Signature:  hex.EncodeToString(an.Signature),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("adjudicator answer: %d %s", rec.Code, rec.Body.String())
	}
	rec, body = do(t, h, "GET", "/api/v1/assessments/"+assessmentID+"/answer", nil)
	if rec.Code != http.StatusOK || body["answerer"] != string(operatorMember) {
		t.Fatalf("read answer: %d %v", rec.Code, body)
	}

	// The harm stays visible in its own typed stream beside the answer.
	rec, body = do(t, h, "GET", "/api/v1/members/"+string(operatorMember)+"/standing", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("standing: %d", rec.Code)
	}
	conduct := body["relations"].(map[string]any)["adjudication-conduct"].(map[string]any)
	if conduct["harm"].(float64) != 1 {
		t.Fatal("the conduct harm must stay visible; an answer annotates, never erases")
	}
	trade := body["relations"].(map[string]any)["trade"].(map[string]any)
	if trade["harm"].(float64) != 0 {
		t.Fatal("the conduct harm must not leak into the trade stream")
	}
}
