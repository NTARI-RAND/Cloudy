// Package enroll drives a frontend through the SoHoLINK coordinator's operator
// onboarding lifecycle:
//
//	apply → register the 7-key set → email verification → conformance A/B → active
//
// These endpoints are plain JSON on the coordinator's PORTAL surface — NOT the
// /v0 node-side wire that internal/coord speaks — so this package carries its
// own minimal HTTP+JSON client rather than reusing coord.Client. It reuses
// internal/opcred for key custody and for computing conformance answers through
// the real protocol canon. Suite C is graded entirely on the coordinator side
// and needs no operator response, so there is no suite-C step here.
//
// The email verification code is out-of-band: verify/start emails a 6-digit
// code and never returns it in an API response. The caller supplies a
// CodeSource to obtain it (an interactive prompt, a mailbox poll, or — in
// tests and local bring-up — a log scrape).
package enroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/opcred"
	"github.com/NTARI-RAND/sohocloud-protocol/operator"
)

// CodeSource yields the out-of-band email verification code. Code blocks until
// the code is available or ctx is done.
type CodeSource interface {
	Code(ctx context.Context) (string, error)
}

// CodeSourceFunc adapts a plain function to a CodeSource.
type CodeSourceFunc func(ctx context.Context) (string, error)

// Code implements CodeSource.
func (f CodeSourceFunc) Code(ctx context.Context) (string, error) { return f(ctx) }

// Config parameterizes one enrollment run.
type Config struct {
	Slug      string         // operator id; the coordinator requires ^[a-z0-9-]{1,64}$
	Name      string         // human-readable operator name
	Email     string         // where the coordinator emails the verification code
	Phone     string         // optional
	SessionID string         // binds the verification code to this client across start/check
	Keyset    *opcred.Keyset // the 7-key set to register
	Code      CodeSource     // supplies the emailed verification code
}

// Result reports the terminal state of an enrollment run.
type Result struct {
	OperatorID        string
	KeysRegistered    int
	Verified          bool
	ConformancePassed bool
	Activated         bool
	RunID             string
}

// Client talks to the coordinator's operator onboarding surface at a portal
// base URL (e.g. "http://portal:8080" on the coordinator's own network, since
// the public edge gates /operators/apply behind the federation disclaimer).
type Client struct {
	base string
	hc   *http.Client
}

// NewClient returns a Client for the coordinator portal at base.
func NewClient(base string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"),
		hc:   &http.Client{Timeout: 30 * time.Second},
	}
}

// WithHTTPClient overrides the HTTP client (tests, custom transports/timeouts).
func (c *Client) WithHTTPClient(hc *http.Client) *Client { c.hc = hc; return c }

// HTTPError is a non-2xx response from the coordinator, carrying the status and
// the coordinator's {"error":"..."} message when present.
type HTTPError struct {
	Method string
	Path   string
	Status int
	Msg    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Msg)
}

// Status reports the HTTP status of err if it is an *HTTPError, else 0.
func Status(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

type apiError struct {
	Err string `json:"error"`
}

// do performs a JSON request. reqBody nil sends no body; respBody nil discards
// the response body. Non-2xx becomes an *HTTPError.
func (c *Client) do(ctx context.Context, method, path string, reqBody, respBody any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal %s %s: %w", method, path, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		var ae apiError
		if json.Unmarshal(raw, &ae) == nil && ae.Err != "" {
			msg = ae.Err
		}
		return &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Msg: msg}
	}
	if respBody != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, respBody); err != nil {
			return fmt.Errorf("decode %s %s response: %w", method, path, err)
		}
	}
	return nil
}

// ---- wire structs (JSON tags are the compatibility contract with the
// coordinator's internal/api onboarding handlers) ----

type applyRequest struct {
	Slug  string `json:"slug"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone,omitempty"`
}

// ApplyResponse is the coordinator's reply to a registration.
type ApplyResponse struct {
	OperatorID      string `json:"operator_id"`
	OnboardingState string `json:"onboarding_state"`
}

type registerKeysRequest struct {
	Algo       string   `json:"algo"`
	PublicKeys []string `json:"public_keys"`
}

type registerKeysResponse struct {
	Registered int `json:"registered"`
}

type verifyStartRequest struct {
	Channel   string `json:"channel"`
	SessionID string `json:"session_id"`
}

type verifyCheckRequest struct {
	Channel   string `json:"channel"`
	SessionID string `json:"session_id"`
	Code      string `json:"code"`
}

type statusResponse struct {
	Status string `json:"status"`
}

type conformanceStartResponse struct {
	RunID       string              `json:"run_id"`
	ChallengesA []opcred.ChallengeA `json:"challenges_a"`
	ChallengesB []opcred.ChallengeB `json:"challenges_b"`
}

type conformanceSubmitRequest struct {
	SuiteA []opcred.ResponseA `json:"suite_a"`
	SuiteB []opcred.ResponseB `json:"suite_b"`
}

// ChallengeResult is one graded conformance challenge.
type ChallengeResult struct {
	ChallengeID string `json:"challenge_id"`
	Suite       string `json:"suite"`
	Passed      bool   `json:"passed"`
	Detail      string `json:"detail"`
}

type conformanceSubmitResponse struct {
	Results   []ChallengeResult `json:"results"`
	Passed    bool              `json:"passed"`
	Activated bool              `json:"activated"`
}

const channelEmail = "email"

// ---- individual steps (each maps to one coordinator endpoint) ----

// Apply registers the operator. A 409 (duplicate slug/email) is returned as an
// *HTTPError so callers can treat a re-run as idempotent.
func (c *Client) Apply(ctx context.Context, cfg Config) (ApplyResponse, error) {
	var out ApplyResponse
	err := c.do(ctx, http.MethodPost, "/operators/apply",
		applyRequest{Slug: cfg.Slug, Name: cfg.Name, Email: cfg.Email, Phone: cfg.Phone}, &out)
	return out, err
}

// RegisterKeys registers the operator's seven Ed25519 public keys, base64-std
// encoded in index order. Re-registering clears any prior conformance pass.
func (c *Client) RegisterKeys(ctx context.Context, slug string, ks *opcred.Keyset) (int, error) {
	pubs := ks.PublicKeys()
	enc := make([]string, len(pubs))
	for i, p := range pubs {
		enc[i] = base64.StdEncoding.EncodeToString(p)
	}
	var out registerKeysResponse
	err := c.do(ctx, http.MethodPost, "/operators/"+slug+"/keys",
		registerKeysRequest{Algo: operator.AlgoEd25519, PublicKeys: enc}, &out)
	return out.Registered, err
}

// VerifyStart asks the coordinator to email a fresh verification code bound to
// sessionID.
func (c *Client) VerifyStart(ctx context.Context, slug, sessionID string) error {
	return c.do(ctx, http.MethodPost, "/operators/"+slug+"/verify/start",
		verifyStartRequest{Channel: channelEmail, SessionID: sessionID}, nil)
}

// VerifyCheck submits the emailed code for sessionID.
func (c *Client) VerifyCheck(ctx context.Context, slug, sessionID, code string) error {
	return c.do(ctx, http.MethodPost, "/operators/"+slug+"/verify/check",
		verifyCheckRequest{Channel: channelEmail, SessionID: sessionID, Code: code}, nil)
}

// ConformanceStart opens a conformance run and returns its challenges. The
// endpoint reads no request body.
func (c *Client) ConformanceStart(ctx context.Context, slug string) (conformanceStartResponse, error) {
	var out conformanceStartResponse
	err := c.do(ctx, http.MethodPost, "/operators/"+slug+"/conformance/start", nil, &out)
	return out, err
}

// AnswerChallenges computes suite A and B responses from the keyset through the
// real protocol canon (opcred.ConformanceResponder). Suite C needs no response.
func AnswerChallenges(slug string, ks *opcred.Keyset, start conformanceStartResponse) (conformanceSubmitRequest, error) {
	r := opcred.NewConformanceResponder(slug, ks)
	req := conformanceSubmitRequest{
		SuiteA: make([]opcred.ResponseA, 0, len(start.ChallengesA)),
		SuiteB: make([]opcred.ResponseB, 0, len(start.ChallengesB)),
	}
	for _, ch := range start.ChallengesA {
		a, err := r.AnswerA(ch)
		if err != nil {
			return conformanceSubmitRequest{}, fmt.Errorf("answer suite A %s: %w", ch.ChallengeID, err)
		}
		req.SuiteA = append(req.SuiteA, a)
	}
	for _, ch := range start.ChallengesB {
		b, err := r.AnswerB(ch)
		if err != nil {
			return conformanceSubmitRequest{}, fmt.Errorf("answer suite B %s: %w", ch.ChallengeID, err)
		}
		req.SuiteB = append(req.SuiteB, b)
	}
	return req, nil
}

// ConformanceSubmit submits answers for a run and returns the grade.
func (c *Client) ConformanceSubmit(ctx context.Context, slug, runID string, req conformanceSubmitRequest) (conformanceSubmitResponse, error) {
	var out conformanceSubmitResponse
	err := c.do(ctx, http.MethodPost, "/operators/"+slug+"/conformance/"+runID+"/submit", req, &out)
	return out, err
}

// Enroll runs the whole lifecycle to activation. It is the reusable entry
// point; each step is also exported for callers that need finer control.
//
// A 409 on Apply is tolerated (the operator already exists — a re-run), since
// RegisterKeys and conformance are idempotent enough to complete enrollment
// against an existing pending operator.
func (c *Client) Enroll(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Keyset == nil {
		return nil, errors.New("enroll: nil keyset")
	}
	if cfg.Code == nil {
		return nil, errors.New("enroll: nil CodeSource")
	}
	res := &Result{OperatorID: cfg.Slug}

	applied, err := c.Apply(ctx, cfg)
	switch {
	case err == nil:
		res.OperatorID = applied.OperatorID
	case Status(err) == http.StatusConflict:
		// Already applied — continue against the existing operator record.
	default:
		return res, fmt.Errorf("apply: %w", err)
	}

	n, err := c.RegisterKeys(ctx, cfg.Slug, cfg.Keyset)
	if err != nil {
		return res, fmt.Errorf("register keys: %w", err)
	}
	res.KeysRegistered = n

	if err := c.VerifyStart(ctx, cfg.Slug, cfg.SessionID); err != nil {
		return res, fmt.Errorf("verify start: %w", err)
	}
	code, err := cfg.Code.Code(ctx)
	if err != nil {
		return res, fmt.Errorf("obtain verification code: %w", err)
	}
	if err := c.VerifyCheck(ctx, cfg.Slug, cfg.SessionID, strings.TrimSpace(code)); err != nil {
		return res, fmt.Errorf("verify check: %w", err)
	}
	res.Verified = true

	start, err := c.ConformanceStart(ctx, cfg.Slug)
	if err != nil {
		return res, fmt.Errorf("conformance start: %w", err)
	}
	res.RunID = start.RunID
	answers, err := AnswerChallenges(cfg.Slug, cfg.Keyset, start)
	if err != nil {
		return res, err
	}
	grade, err := c.ConformanceSubmit(ctx, cfg.Slug, start.RunID, answers)
	if err != nil {
		return res, fmt.Errorf("conformance submit: %w", err)
	}
	res.ConformancePassed = grade.Passed
	res.Activated = grade.Activated
	if !grade.Passed {
		return res, fmt.Errorf("conformance failed: %s", failedDetail(grade.Results))
	}
	return res, nil
}

func failedDetail(results []ChallengeResult) string {
	var b strings.Builder
	for _, r := range results {
		if !r.Passed {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s/%s: %s", r.Suite, r.ChallengeID, r.Detail)
		}
	}
	if b.Len() == 0 {
		return "no per-challenge detail"
	}
	return b.String()
}
