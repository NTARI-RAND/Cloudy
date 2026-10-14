package consumerapi

// JFA conformance bindings at the composition root, where the covenant's
// adjudication anchor is wired to the dispute registry.
//
// Test names carry the Janus registry ID they bind (jfa-conformance-suite.py
// in NTARI-RAND/Janus), so `jfa-conformance-suite.py --bindings` and a CI log
// parser can map a PASS/FAIL back to the invariant: TestInvariant_<ID>_<Name>,
// with any "-" in the ID written "_".

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/covenant"
	"github.com/NTARI-RAND/Cloudy/internal/dispute"
	"github.com/NTARI-RAND/Cloudy/internal/record"
)

// TestInvariant_COV_adjudicators_PartiesRateTheAdjudicator binds registry ID
// COV-adjudicators: "adjudication conduct ratable by the parties to the
// adjudication — the operator on a platform, the witnesses across
// platforms."
//
// On a platform the operator adjudicates (COV-operators-adjudicate), so the
// operator is the referee who must stand inside the reputation system it
// enforces. Over the public API this binding proves:
//
//   - BOTH parties to a claim — complainant and respondent — can rate the
//     operator's adjudication conduct, at any level, a No Trust included;
//   - nobody else can: not a stranger, not a member who traded on the
//     exchange but is no party to the claim, not anyone on an exchange with
//     no claim, and not the operator rating itself;
//   - only the adjudicator can be rated in this relation: a party cannot use
//     it to rate the other party;
//   - the ratings land in the operator's standing as their own typed
//     distribution, never pooled into trade, with the harm counted;
//   - the operator can answer each rating, and only the operator can.
//
// Residual, named rather than hidden: the cross-platform half — witnesses
// rated by the parties to a dispute they adjudicate — has no code to test
// yet, because cross-platform adjudication at the witness layer
// (COV-witness-adjudication) is not built. The adjudication anchor here
// accepts only the platform operator as subject; when witness adjudication
// lands, that anchor must widen to the panel and this binding must grow.
func TestInvariant_COV_adjudicators_PartiesRateTheAdjudicator(t *testing.T) {
	s, err := NewServer(platform)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	op := s.operatorMember

	pubA, privA := key(0x61) // complainant
	pubB, privB := key(0x62) // respondent
	pubC, privC := key(0x63) // stranger
	pubD, privD := key(0x64) // traded with A, never party to the claim
	for _, m := range []struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}{{pubA, privA}, {pubB, privB}, {pubC, privC}, {pubD, privD}} {
		registerMember(t, h, m.pub, m.priv)
	}
	disputed := sealExchange(t, h, pubA, privA, pubB, privB)
	openClaim(t, h, pubA, privA, pubB, disputed)
	unclaimed := sealExchange(t, h, pubA, privA, pubD, privD)

	mem := func(pub ed25519.PublicKey) covenant.MemberID { return covenant.MemberIDFor(platform, pub) }

	// Both parties rate the operator's conduct — one with the harm level.
	idA := rate(t, h, privA, mem(pubA), op, disputed, covenant.LevelNoTrust, http.StatusOK)
	idB := rate(t, h, privB, mem(pubB), op, disputed, covenant.LevelBasicSatisfaction, http.StatusOK)

	// Nobody else can.
	refused := []struct {
		name     string
		priv     ed25519.PrivateKey
		assessor covenant.MemberID
		subject  covenant.MemberID
		exchange string
	}{
		{"a stranger", privC, mem(pubC), op, disputed},
		{"a trader who is no party to the claim", privD, mem(pubD), op, disputed},
		{"a party, on an exchange with no claim", privA, mem(pubA), op, unclaimed},
		{"the other trader on that unclaimed exchange", privD, mem(pubD), op, unclaimed},
		{"the operator, rating itself", s.operatorPriv, op, op, disputed},
		{"a party rating the other party as if adjudicator", privA, mem(pubA), mem(pubB), disputed},
	}
	// Each refusal uses a category no assessor has used yet, so the only
	// possible reason for a 400 is the anchor (a duplicate would be 409).
	for _, r := range refused {
		r := r
		t.Run("refused: "+r.name, func(t *testing.T) {
			rateIn(t, h, r.priv, r.assessor, r.subject, r.exchange, "reliability", covenant.LevelDelight, http.StatusBadRequest)
		})
	}

	// The ratings are the operator's own typed distribution.
	rec, body := do(t, h, "GET", "/api/v1/members/"+string(op)+"/standing", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("standing: %d", rec.Code)
	}
	rels := body["relations"].(map[string]any)
	conduct := rels["adjudication-conduct"].(map[string]any)
	overall := conduct["overall"].(map[string]any)
	if overall["total"].(float64) != 2 {
		t.Errorf("adjudication-conduct total = %v, want 2 (both parties, nobody else)", overall["total"])
	}
	counts := overall["counts"].(map[string]any)
	if counts[covenant.LevelNoTrust.String()].(float64) != 1 || counts[covenant.LevelBasicSatisfaction.String()].(float64) != 1 {
		t.Errorf("adjudication-conduct counts = %v, want one No Trust and one Basic Satisfaction", counts)
	}
	if conduct["harm"].(float64) != 1 {
		t.Errorf("adjudication-conduct harm = %v, want 1", conduct["harm"])
	}
	if trade := rels["trade"].(map[string]any)["overall"].(map[string]any); trade["total"].(float64) != 0 {
		t.Errorf("trade total = %v, want 0: conduct ratings must never pool into trade", trade["total"])
	}

	// The operator answers each rating; a party cannot answer for it.
	answer(t, h, privA, mem(pubA), idA, http.StatusBadRequest)
	answer(t, h, s.operatorPriv, op, idA, http.StatusOK)
	answer(t, h, s.operatorPriv, op, idB, http.StatusOK)
}

// openClaim files a complainant-signed dispute over exchange through the API.
func openClaim(t *testing.T, h http.Handler, pubA ed25519.PublicKey, privA ed25519.PrivateKey, pubB ed25519.PublicKey, exchange string) {
	t.Helper()
	exRaw, _ := hex.DecodeString(exchange)
	var ex dispute.ExchangeRef
	copy(ex[:], exRaw)
	o, err := dispute.NewOpening(platform, pubA, pubB, ex, sha256.Sum256([]byte("grievance")), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Sign(privA); err != nil {
		t.Fatal(err)
	}
	oid := o.ID()
	typeHash := sha256.Sum256([]byte("trade-harm"))
	commitment := record.FilingCommitment{
		Claim: record.Hash(oid), Exchange: record.Hash(ex), TypeHash: record.Hash(typeHash),
		At: o.OpenedAt, Filer: pubA,
	}
	commitment.Sign(privA)
	req := openDisputeRequest{
		Complainant: hex.EncodeToString(pubA),
		Respondent:  hex.EncodeToString(pubB),
		Exchange:    exchange,
		ReasonHash:  hex.EncodeToString(o.ReasonHash[:]),
		Nonce:       hex.EncodeToString(o.Nonce[:]),
		OpenedAt:    o.OpenedAt.Format(time.RFC3339Nano),
		Signature:   hex.EncodeToString(o.Signature),
	}
	req.Filing.TypeHash = hex.EncodeToString(typeHash[:])
	req.Filing.At = o.OpenedAt.Format(time.RFC3339Nano)
	req.Filing.Signature = hex.EncodeToString(commitment.Signature)
	if rec, _ := do(t, h, "POST", "/api/v1/disputes", req); rec.Code != http.StatusOK {
		t.Fatalf("open dispute: %d %s", rec.Code, rec.Body.String())
	}
}

// rate posts an adjudication-conduct assessment and checks the status code;
// it returns the assessment ID on success.
func rate(t *testing.T, h http.Handler, priv ed25519.PrivateKey, assessor, subject covenant.MemberID, exchange string, level covenant.Level, want int) string {
	return rateIn(t, h, priv, assessor, subject, exchange, "support", level, want)
}

// rateIn is rate with an explicit category. The covenant de-duplicates on
// (assessor, exchange, relation, category), so a refusal case must use a
// category the same assessor has not already used on that exchange —
// otherwise it would be refused as a duplicate and pass for the wrong reason.
func rateIn(t *testing.T, h http.Handler, priv ed25519.PrivateKey, assessor, subject covenant.MemberID, exchange, category string, level covenant.Level, want int) string {
	t.Helper()
	exRaw, _ := hex.DecodeString(exchange)
	var ex covenant.ExchangeRef
	copy(ex[:], exRaw)
	a := covenant.Assessment{
		Assessor: assessor, Subject: subject, Exchange: ex,
		Relation: covenant.RelationAdjudicationConduct, Category: category,
		Level: level, IssuedAt: time.Now().UTC(),
	}
	req := assessmentRequest{
		Assessor: string(assessor), Subject: string(subject), Exchange: exchange,
		Relation: string(a.Relation), Category: a.Category, Level: int8(level),
		IssuedAt: a.IssuedAt.Format(time.RFC3339Nano),
	}
	if level == covenant.LevelNoTrust {
		a.CommentHash = sha256.Sum256([]byte("justifying comment, member-local"))
		req.CommentHash = hex.EncodeToString(a.CommentHash[:])
	}
	a.Sign(priv)
	req.Signature = hex.EncodeToString(a.Signature)
	rec, body := do(t, h, "POST", "/api/v1/assessments", req)
	if rec.Code != want {
		t.Fatalf("conduct rating by %s of %s on %s…: code %d, want %d (%s)", assessor[:8], subject[:8], exchange[:8], rec.Code, want, rec.Body.String())
	}
	id, _ := body["id"].(string)
	return id
}

// answer posts an answer to assessment id and checks the status code.
func answer(t *testing.T, h http.Handler, priv ed25519.PrivateKey, answerer covenant.MemberID, id string, want int) {
	t.Helper()
	digest := sha256.Sum256([]byte("answer, member-local"))
	an := covenant.Answer{Answerer: answerer, AnswerHash: digest, IssuedAt: time.Now().UTC()}
	raw, _ := hex.DecodeString(id)
	copy(an.Assessment[:], raw)
	an.Sign(priv)
	rec, _ := do(t, h, "POST", "/api/v1/assessments/"+id+"/answers", answerRequest{
		Answerer: string(answerer), AnswerHash: hex.EncodeToString(digest[:]),
		IssuedAt: an.IssuedAt.Format(time.RFC3339Nano), Signature: hex.EncodeToString(an.Signature),
	})
	if rec.Code != want {
		t.Fatalf("answer by %s…: code %d, want %d (%s)", answerer[:8], rec.Code, want, rec.Body.String())
	}
}
