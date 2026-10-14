package dispute

// JFA conformance bindings for the dispute layer.
//
// Test names carry the Janus registry ID they bind (jfa-conformance-suite.py
// in NTARI-RAND/Janus), so `jfa-conformance-suite.py --bindings` and a CI log
// parser can map a PASS/FAIL back to the invariant: TestInvariant_<ID>_<Name>,
// with any "-" in the ID written "_".

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestInvariant_COV_operators_adjudicate_OperatorRulesOnItsPlatform binds
// registry ID COV-operators-adjudicate: "adjudication of apparent covenant
// breaches performed by platform operators."
//
// The deciding role is the platform's Charter — the operator's own
// adjudicator roster, configured at the composition root for exactly one
// platform. This binding proves that role cannot be taken by anyone else:
//
//   - only a threshold of the Charter's adjudicators resolves a case; the
//     complainant, the respondent, both of them together, a witness, or a
//     stranger cannot, however many sign;
//   - a ruling is bound to its platform: another platform's ruling, or
//     another platform's roster, never resolves a case here;
//   - Rule is the only path to a resolution: the Registry's whole API is
//     pinned, a Withdrawal is the complainant's alone and ends the case
//     without a finding, and nothing else moves a case's state.
//
// Out of scope here, named: whether an adjudicator on the roster is barred
// from ruling on a case to which it is itself a party is
// COV-operator-dispute-witnesses, an instrument-bound invariant (P1-001
// §10.9), and is not checked by this package today.
func TestInvariant_COV_operators_adjudicate_OperatorRulesOnItsPlatform(t *testing.T) {
	t.Run("only the charter's roster resolves a case", testOperatorsOnlyRosterRules)
	t.Run("a ruling is bound to its platform", testOperatorsPlatformBound)
	t.Run("Rule is the only path to a resolution", testOperatorsOnlyPath)
}

// openCase opens a fresh case on f and returns its ID and exchange.
func openCase(t *testing.T, f *fixture, ex ExchangeRef) DisputeID {
	t.Helper()
	f.anchors.seal(ex, f.cPub, f.rPub)
	id, err := f.reg.Open(mkOpening(t, f.cPub, f.cKey, f.rPub, ex))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return id
}

func ruling(f *fixture, id DisputeID, ex ExchangeRef) Ruling {
	return NewEscrowRuling(f.charter.Platform, id, ex, FindingForComplainant,
		ActionRefundComplainant, 10, sha256.Sum256([]byte("rationale")), time.Unix(1700000000, 0).UTC())
}

func testOperatorsOnlyRosterRules(t *testing.T) {
	f := newFixture(t, 2)
	ex := ref(0x51)
	id := openCase(t, f, ex)
	_, witness := genKeyT(t)
	_, stranger := genKeyT(t)

	impostors := []struct {
		name    string
		signers []ed25519.PrivateKey
	}{
		{"complainant", []ed25519.PrivateKey{f.cKey}},
		{"respondent", []ed25519.PrivateKey{f.rKey}},
		{"both parties together", []ed25519.PrivateKey{f.cKey, f.rKey}},
		{"a witness", []ed25519.PrivateKey{witness}},
		{"a stranger", []ed25519.PrivateKey{stranger}},
		{"parties, witness and stranger", []ed25519.PrivateKey{f.cKey, f.rKey, witness, stranger}},
		{"one adjudicator below threshold", []ed25519.PrivateKey{f.adj1}},
		{"one adjudicator twice", []ed25519.PrivateKey{f.adj1, f.adj1}},
		{"one adjudicator plus a party", []ed25519.PrivateKey{f.adj1, f.cKey}},
	}
	for _, imp := range impostors {
		r := ruling(f, id, ex)
		for _, k := range imp.signers {
			r.Sign(k)
		}
		if err := f.reg.Rule(r); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("ruling signed by %s = %v, want ErrUnauthorized: only the operator's roster adjudicates", imp.name, err)
		}
	}
	c, err := f.reg.Case(id)
	if err != nil {
		t.Fatalf("Case: %v", err)
	}
	if c.State() != StateOpen {
		t.Fatalf("case is %s after refused rulings, want open", c.State())
	}

	// The roster, at threshold, resolves it.
	if err := f.reg.Rule(f.signRuling(ruling(f, id, ex), 2)); err != nil {
		t.Fatalf("roster ruling: %v", err)
	}
	if c, _ := f.reg.Case(id); c.State() != StateResolved {
		t.Fatalf("case is %s after the roster ruled, want resolved", c.State())
	}
}

func testOperatorsPlatformBound(t *testing.T) {
	f := newFixture(t, 1)
	ex := ref(0x52)
	id := openCase(t, f, ex)

	// The right roster, the wrong platform.
	r := ruling(f, id, ex)
	r.Platform = "another-platform"
	r.Sign(f.adj1)
	if err := f.reg.Rule(r); err == nil {
		t.Error("a ruling for another platform resolved a case here")
	}

	// Another platform's roster, signing for this platform.
	other := newFixture(t, 1)
	r = ruling(f, id, ex)
	r.Sign(other.adj1)
	if err := f.reg.Rule(r); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("another platform's adjudicator = %v, want ErrUnauthorized", err)
	}
	if c, _ := f.reg.Case(id); c.State() != StateOpen {
		t.Fatalf("case is %s, want open", c.State())
	}
}

// registryAPI is every exported method the Registry may ship. A new one is
// a possible second path to a resolution and fails until reviewed.
var registryAPI = map[string]bool{"Open": true, "Rule": true, "Withdraw": true, "Case": true}

func testOperatorsOnlyPath(t *testing.T) {
	typ := reflect.TypeOf(&Registry{})
	got := map[string]bool{}
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		got[name] = true
		if !registryAPI[name] {
			t.Errorf("Registry exports %s, not in registryAPI: a new method is a possible way to resolve a case without the operator's roster", name)
		}
	}
	for name := range registryAPI {
		if !got[name] {
			t.Errorf("registryAPI lists %s, which Registry no longer exports — remove it", name)
		}
	}

	// Case state is folded in exactly one place, and only a Ruling sets
	// StateResolved there.
	resolvedSites := 0
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			as, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, rhs := range as.Rhs {
				if id, ok := rhs.(*ast.Ident); ok && id.Name == "StateResolved" {
					resolvedSites++
				}
			}
			return true
		})
	}
	if resolvedSites != 1 {
		t.Errorf("StateResolved is assigned at %d sites, want exactly 1 (the Ruling fold in Case)", resolvedSites)
	}

	// A Withdrawal is the complainant's alone and carries no finding.
	f := newFixture(t, 1)
	ex := ref(0x53)
	id := openCase(t, f, ex)
	w := Withdrawal{Platform: f.charter.Platform, Dispute: id, WithdrawnAt: time.Unix(1700000100, 0).UTC()}
	w.Sign(f.adj1)
	if err := f.reg.Withdraw(w); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("adjudicator-signed withdrawal = %v, want ErrUnauthorized", err)
	}
	w.Sign(f.cKey)
	if err := f.reg.Withdraw(w); err != nil {
		t.Fatalf("complainant withdrawal: %v", err)
	}
	c, _ := f.reg.Case(id)
	if _, found := c.Finding(); c.State() != StateWithdrawn || found {
		t.Errorf("after withdrawal: state %s, finding present %v; want withdrawn with no finding", c.State(), found)
	}
}
