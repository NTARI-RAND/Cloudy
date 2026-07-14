package enroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NTARI-RAND/Cloudy/internal/opcred"
	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// mockCoordinator is a minimal stand-in for SoHoLINK's operator onboarding
// surface. It mirrors the real handlers' routes and JSON shapes, and — the
// point of the test — grades conformance with the REAL protocol operator
// package (byte-equality oracle for suite A, ConformanceResponse.Verify for A,
// OperatorTransmission.Verify for B). If the Cloudy client produces answers the
// real verifier rejects, this test fails.
type mockCoordinator struct {
	keymap     map[int]operator.KeyRecord
	chA        map[string]opcred.ChallengeA // by challenge_id
	chB        map[string]opcred.ChallengeB
	issuedCode string
	verified   bool
	confPass   bool
}

func newMockCoordinator() *mockCoordinator {
	return &mockCoordinator{
		chA:        map[string]opcred.ChallengeA{},
		chB:        map[string]opcred.ChallengeB{},
		issuedCode: "424242",
	}
}

func (m *mockCoordinator) server() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /operators/apply", func(w http.ResponseWriter, r *http.Request) {
		var req applyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, 201, ApplyResponse{OperatorID: req.Slug, OnboardingState: "pending_verification"})
	})

	mux.HandleFunc("POST /operators/{id}/keys", func(w http.ResponseWriter, r *http.Request) {
		var req registerKeysRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad json"}`, 400)
			return
		}
		if len(req.PublicKeys) != operator.KeyIndexCount {
			http.Error(w, `{"error":"need exactly 7 keys"}`, 400)
			return
		}
		m.keymap = map[int]operator.KeyRecord{}
		for i, b64 := range req.PublicKeys {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil || len(raw) != 32 {
				http.Error(w, `{"error":"bad key"}`, 400)
				return
			}
			m.keymap[i] = operator.KeyRecord{PublicKey: raw, Algo: operator.AlgoEd25519}
		}
		m.confPass = false // re-registering clears a prior pass
		writeJSON(w, 200, registerKeysResponse{Registered: len(req.PublicKeys)})
	})

	mux.HandleFunc("POST /operators/{id}/verify/start", func(w http.ResponseWriter, r *http.Request) {
		var req verifyStartRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.SessionID == "" {
			http.Error(w, `{"error":"session_id required"}`, 400)
			return
		}
		writeJSON(w, 200, statusResponse{Status: "sent"})
	})

	mux.HandleFunc("POST /operators/{id}/verify/check", func(w http.ResponseWriter, r *http.Request) {
		var req verifyCheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Code != m.issuedCode {
			http.Error(w, `{"error":"code mismatch"}`, 401)
			return
		}
		m.verified = true
		writeJSON(w, 200, statusResponse{Status: "verified"})
	})

	mux.HandleFunc("POST /operators/{id}/conformance/start", func(w http.ResponseWriter, r *http.Request) {
		if len(m.keymap) != operator.KeyIndexCount {
			http.Error(w, `{"error":"register all seven keys before starting conformance"}`, 400)
			return
		}
		id := r.PathValue("id")
		a := opcred.ChallengeA{
			ChallengeID: "a-1", OperatorID: id, TsUnixNano: 1_700_000_000_000_000_000,
			Nonce: bytes.Repeat([]byte{0xA1}, operator.MinNonceLen), Seq: 1,
			Algo: operator.AlgoEd25519, Idx0: 0, Idx1: 1,
		}
		b := opcred.ChallengeB{
			ChallengeID: "b-1", OperatorID: id, TsUnixNano: 1_700_000_000_000_000_001,
			Nonce: bytes.Repeat([]byte{0xB2}, operator.MinNonceLen), Seq: 2,
			Algo: operator.AlgoEd25519,
		}
		m.chA[a.ChallengeID] = a
		m.chB[b.ChallengeID] = b
		writeJSON(w, 200, conformanceStartResponse{
			RunID: "run-1", ChallengesA: []opcred.ChallengeA{a}, ChallengesB: []opcred.ChallengeB{b},
		})
	})

	mux.HandleFunc("POST /operators/{id}/conformance/{run}/submit", func(w http.ResponseWriter, r *http.Request) {
		var req conformanceSubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad json"}`, 400)
			return
		}
		var results []ChallengeResult
		allPass := true

		for _, ra := range req.SuiteA {
			ch, ok := m.chA[ra.ChallengeID]
			pass := false
			detail := "unknown challenge"
			if ok {
				// Oracle: the canonical bytes the coordinator expects.
				oracle := operator.OperatorTransmission{
					OperatorID: ch.OperatorID, TsUnixNano: ch.TsUnixNano, Nonce: ch.Nonce,
					Seq: ch.Seq, Algo: ch.Algo, Idx0: ch.Idx0, Idx1: ch.Idx1,
				}.CanonicalBytes()
				if !bytes.Equal(ra.CanonicalBytes, oracle) {
					detail = "canonical bytes mismatch"
				} else {
					cr := operator.ConformanceResponse{
						OperatorID: ch.OperatorID, Challenge: ra.CanonicalBytes, Algo: ch.Algo,
						Idx0: ra.Idx0, Idx1: ra.Idx1, Sig0: ra.Sig0, Sig1: ra.Sig1,
					}
					if err := cr.Verify(m.keymap); err != nil {
						detail = "verify: " + err.Error()
					} else {
						pass, detail = true, "ok"
					}
				}
			}
			allPass = allPass && pass
			results = append(results, ChallengeResult{ChallengeID: ra.ChallengeID, Suite: "A", Passed: pass, Detail: detail})
		}

		for _, rb := range req.SuiteB {
			ch, ok := m.chB[rb.ChallengeID]
			pass := false
			detail := "unknown challenge"
			if ok {
				tx := operator.OperatorTransmission{
					OperatorID: ch.OperatorID, TsUnixNano: ch.TsUnixNano, Nonce: ch.Nonce,
					Seq: ch.Seq, Algo: ch.Algo, Idx0: rb.Idx0, Idx1: rb.Idx1, Sig0: rb.Sig0, Sig1: rb.Sig1,
				}
				if err := tx.Verify(m.keymap); err != nil {
					detail = "verify: " + err.Error()
				} else {
					pass, detail = true, "ok"
				}
			}
			allPass = allPass && pass
			results = append(results, ChallengeResult{ChallengeID: rb.ChallengeID, Suite: "B", Passed: pass, Detail: detail})
		}

		// Suite C is graded coordinator-side and always evaluated here.
		results = append(results, ChallengeResult{ChallengeID: "c-1", Suite: "C", Passed: true, Detail: "server-side"})

		m.confPass = allPass
		activated := allPass && m.verified
		writeJSON(w, 200, conformanceSubmitResponse{Results: results, Passed: allPass, Activated: activated})
	})

	return httptest.NewServer(mux)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func TestEnroll_HappyPath(t *testing.T) {
	mock := newMockCoordinator()
	srv := mock.server()
	defer srv.Close()

	ks, err := opcred.GenerateKeyset()
	if err != nil {
		t.Fatalf("GenerateKeyset: %v", err)
	}

	c := NewClient(srv.URL)
	res, err := c.Enroll(context.Background(), Config{
		Slug:      "cloudy-test",
		Name:      "Cloudy Test",
		Email:     "ops@cloudy.example",
		SessionID: "sess-abc",
		Keyset:    ks,
		Code:      CodeSourceFunc(func(context.Context) (string, error) { return mock.issuedCode, nil }),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.KeysRegistered != operator.KeyIndexCount {
		t.Errorf("KeysRegistered = %d, want %d", res.KeysRegistered, operator.KeyIndexCount)
	}
	if !res.Verified {
		t.Error("Verified = false, want true")
	}
	if !res.ConformancePassed {
		t.Error("ConformancePassed = false, want true")
	}
	if !res.Activated {
		t.Error("Activated = false, want true")
	}
	if res.RunID != "run-1" {
		t.Errorf("RunID = %q, want run-1", res.RunID)
	}
	if !mock.verified || !mock.confPass {
		t.Errorf("coordinator state: verified=%v confPass=%v", mock.verified, mock.confPass)
	}
}

// TestEnroll_ForeignKeysRejected proves the mock's grading is real, not a
// rubber stamp: answers signed by a keyset OTHER than the registered one must
// fail the coordinator's protocol Verify.
func TestEnroll_ForeignKeysRejected(t *testing.T) {
	mock := newMockCoordinator()
	srv := mock.server()
	defer srv.Close()

	registered, _ := opcred.GenerateKeyset()
	foreign, _ := opcred.GenerateKeyset()
	c := NewClient(srv.URL)
	ctx := context.Background()

	if _, err := c.RegisterKeys(ctx, "op", registered); err != nil {
		t.Fatalf("RegisterKeys: %v", err)
	}
	start, err := c.ConformanceStart(ctx, "op")
	if err != nil {
		t.Fatalf("ConformanceStart: %v", err)
	}
	// Answer with the WRONG keyset.
	answers, err := AnswerChallenges("op", foreign, start)
	if err != nil {
		t.Fatalf("AnswerChallenges: %v", err)
	}
	grade, err := c.ConformanceSubmit(ctx, "op", start.RunID, answers)
	if err != nil {
		t.Fatalf("ConformanceSubmit: %v", err)
	}
	if grade.Passed {
		t.Fatal("conformance passed with foreign keys; grading is not verifying signatures")
	}
}

func TestApply_ConflictIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"operator exists"}`, http.StatusConflict)
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	_, err := c.Apply(context.Background(), Config{Slug: "dup"})
	if Status(err) != http.StatusConflict {
		t.Fatalf("Status(err) = %d, want 409 (err=%v)", Status(err), err)
	}
}
