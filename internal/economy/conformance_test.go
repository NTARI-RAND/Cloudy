package economy

// JFA conformance bindings for the economy layer.
//
// Test names carry the Janus registry ID they bind (jfa-conformance-suite.py
// in NTARI-RAND/Janus), so a CI log parser can map a PASS/FAIL back to the
// invariant: TestInvariant_<ID>_<Name>, with any "-" in the ID written "_".

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestInvariant_L1_ZeroSumBalance binds registry ID L1: "each exchange moves
// two balances netting to zero."
//
// TestZeroSum already proves the end-state sum on one ledger, driven
// serially. This binding adds what L1 needs beyond that:
//
//  1. Concurrency: several payers post at once, through two Ledgers sharing
//     one Store, so admission races and catch-up are exercised.
//  2. Per-exchange netting: every admitted record in the store moves exactly
//     two accounts, by -amount and +amount — not just a sum that happens to
//     come out zero at the end.
//  3. Determinism: balances are a function of the sealed record, so a fresh
//     Open over the same store reproduces every balance and the zero sum.
func TestInvariant_L1_ZeroSumBalance(t *testing.T) {
	const (
		debitCap      = 300
		spendsPerPeer = 60
	)
	f := newFixture(t, ModeCredit, debitCap, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
	l2, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("second Open over the shared store: %v", err)
	}
	ledgers := []*Ledger{f.ledger, l2}

	// One goroutine per payer, so each payer's nonces stay sequential while
	// different payers race each other across both ledgers.
	var wg sync.WaitGroup
	admitted := make([]int, len(f.members))
	errs := make(chan error, len(f.members))
	for pi := range f.members {
		wg.Add(1)
		go func(pi int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(pi) + 1))
			payer := f.members[pi]
			var nonce uint64
			for i := 0; i < spendsPerPeer; i++ {
				ti := (pi + 1 + rng.Intn(len(f.members)-1)) % len(f.members)
				s := f.spend(payer, f.members[ti], Amount(rng.Intn(120)+1), nonce+1)
				switch err := ledgers[i%2].Post(s); {
				case err == nil:
					nonce++
					admitted[pi]++
				case errors.Is(err, ErrLimit):
					// The uniform cap is the only legitimate refusal here.
				default:
					errs <- err
					return
				}
			}
		}(pi)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("unexpected rejection under concurrency: %v", err)
	}

	total := 0
	for _, n := range admitted {
		total += n
	}
	if total == 0 {
		t.Fatal("no spends admitted; the binding exercised nothing")
	}

	// (2) Every sealed exchange nets to zero on its own.
	recs, err := f.store.All()
	if err != nil {
		t.Fatalf("store.All: %v", err)
	}
	if len(recs) != total {
		t.Fatalf("store holds %d records, want %d admitted spends", len(recs), total)
	}
	fold := map[AccountID]int64{}
	for i, r := range recs {
		s, ok := r.(Spend)
		if !ok {
			t.Fatalf("record %d is %T, want Spend", i, r)
		}
		if s.From == s.To {
			t.Fatalf("record %d moves one account, want two", i)
		}
		before := fold[s.From] + fold[s.To]
		fold[s.From] -= int64(s.Amount)
		fold[s.To] += int64(s.Amount)
		if after := fold[s.From] + fold[s.To]; after != before {
			t.Fatalf("record %d changed the pair's sum by %d, want 0", i, after-before)
		}
	}

	// End state: the sum over all accounts is exactly zero, on both live
	// ledgers (after catch-up) and on a fresh replay.
	reopened, err := Open(f.genesis, f.dir, f.store)
	if err != nil {
		t.Fatalf("reopen for replay: %v", err)
	}
	// The live ledgers may each lag the store (a ledger only catches up when
	// it posts), so they are checked for a zero sum over their own applied
	// prefix; the fresh replay is checked against the full fold.
	var sum int64
	for _, m := range f.members {
		b := int64(reopened.Balance(m.id))
		if b != fold[m.id] {
			t.Fatalf("replayed balance %d != folded balance %d: balances must be a function of the record", b, fold[m.id])
		}
		if b < -debitCap {
			t.Fatalf("balance %d below the uniform cap -%d", b, debitCap)
		}
		sum += b
	}
	if sum != 0 {
		t.Fatalf("sum of balances = %d after %d concurrent spends, want exactly 0", sum, total)
	}
	for li, l := range ledgers {
		var s int64
		for _, m := range f.members {
			s += int64(l.Balance(m.id))
		}
		if s != 0 {
			t.Fatalf("live ledger %d sum = %d, want exactly 0 at every applied prefix", li, s)
		}
	}
}

// TestInvariant_L2_EarnedNeverBought binds registry ID L2: "earned never
// bought and never redeemable for fiat" — no purchase path, no redemption
// path.
//
// The package doc says purchase and redemption are absent APIs. Absence is
// only a guarantee if adding one fails a test, so every surface that could
// grow a path is pinned to an allowlist:
//
//   - the ledger's whole API: exactly the methods and constructors listed;
//   - the record union: exactly Spend and PolicyChange can enter a store;
//   - the record shapes: every field named, no fiat-shaped field possible;
//   - the import graph: the ledger sees only the standard library and the
//     protocol's canon, so it cannot reach the fiat rail, the market, or
//     dispute escrow;
//   - the module: no exported buy/redeem/cash-out/payout/top-up verb and no
//     such route anywhere, and no function that touches the fiat rail also
//     moves credit.
//
// And at runtime: in escrow mode no credit exists to buy, and in credit mode
// a balance rises only as the payee of another member's signed spend.
func TestInvariant_L2_EarnedNeverBought(t *testing.T) {
	t.Run("ledger API is exactly the allowlist", testL2LedgerAPI)
	t.Run("only spends and policy changes are records", testL2RecordUnion)
	t.Run("record fields are exactly the allowlist", testEconomyFieldAllowlist)
	t.Run("ledger imports only stdlib and canon", testEconomyImports)
	t.Run("no purchase or redemption path in the module", testL2NoMoneyPath)
	t.Run("credit is created only by a member's own signed spend", testL2EarnedAtRuntime)
}

// ledgerAPI is every exported method and package-level function the economy
// package may ship. Adding one fails testL2LedgerAPI until it is listed —
// the review moment for any new path that could move credit.
var ledgerAPI = map[string]bool{
	// package-level
	"Open": true, "AccountIDFor": true, "NewMemStore": true,
	// *Ledger — Post is the ONLY credit-moving verb
	"Ledger.Post": true, "Ledger.Enact": true, "Ledger.Policy": true, "Ledger.Balance": true,
	// records
	"Spend.CanonicalBytes": true, "Spend.Sign": true, "Spend.Verify": true,
	"PolicyChange.CanonicalBytes": true, "PolicyChange.Sign": true, "PolicyChange.Verify": true,
	// store
	"MemStore.Append": true, "MemStore.All": true,
}

func testL2LedgerAPI(t *testing.T) {
	got := map[string]bool{}
	for _, f := range economySource(t) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			name := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				name = econReceiverName(fn.Recv.List[0].Type) + "." + name
			}
			got[name] = true
			if !ledgerAPI[name] {
				t.Errorf("economy exports %s, which is not in ledgerAPI: a new exported function or method is a possible purchase or redemption path — list it only after review", name)
			}
		}
	}
	for name := range ledgerAPI {
		if !got[name] {
			t.Errorf("ledgerAPI lists %s, which economy no longer exports — remove it", name)
		}
	}
}

func testL2RecordUnion(t *testing.T) {
	// The Record union is sealed by an unexported record() method; only the
	// types that declare it can be stored. Pin that set.
	want := map[string]bool{"Spend": true, "PolicyChange": true}
	got := map[string]bool{}
	for _, f := range economySource(t) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "record" || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			got[econReceiverName(fn.Recv.List[0].Type)] = true
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Record union members = %v, want exactly %v: a new record type is a new way to move credit", keys(got), keys(want))
	}

	// And a foreign record smuggled into a store never opens: replay admits
	// exactly Spend and PolicyChange.
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02)
	type grant struct{ Spend } // embeds Spend to inherit record(), the classic smuggle
	bad := NewMemStore()
	if err := bad.Append(0, grant{f.spend(f.members[0], f.members[1], 10, 1)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := Open(f.genesis, f.dir, bad); !errors.Is(err, ErrTampered) {
		t.Errorf("Open over a store holding a smuggled record type = %v, want ErrTampered", err)
	}
}

// economyFields is every field of every type the economy stores or is
// configured with, as Type.Field: kind. A fiat amount, currency code,
// payment reference, per-account limit, or memo cannot be added without
// failing testEconomyFieldAllowlist — and the only strings are the
// platform identity and the two-valued mode.
var economyFields = map[string]reflect.Kind{
	"Spend.Platform":        reflect.String,
	"Spend.From":            reflect.Array,
	"Spend.To":              reflect.Array,
	"Spend.Amount":          reflect.Uint64,
	"Spend.ExchangeHash":    reflect.Array,
	"Spend.IssuedAt":        reflect.Struct, // time.Time
	"Spend.Nonce":           reflect.Uint64,
	"Spend.Signature":       reflect.Slice,
	"PolicyChange.Platform": reflect.String,
	"PolicyChange.Policy":   reflect.Struct,
	"PolicyChange.Version":  reflect.Uint64,
	"PolicyChange.At":       reflect.Struct, // time.Time
	"PolicyChange.Sigs":     reflect.Slice,
	"Policy.Mode":           reflect.String,
	"Policy.DebitCap":       reflect.Uint64,
	"Genesis.Platform":      reflect.String,
	"Genesis.Stewards":      reflect.Slice,
	"Genesis.Threshold":     reflect.Int,
	"Genesis.Policy":        reflect.Struct,
}

func testEconomyFieldAllowlist(t *testing.T) {
	timeType := reflect.TypeOf(time.Time{})
	policyType := reflect.TypeOf(Policy{})
	seen := map[string]bool{}
	for _, v := range []interface{}{Spend{}, PolicyChange{}, Policy{}, Genesis{}} {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			key := typ.Name() + "." + f.Name
			seen[key] = true
			want, ok := economyFields[key]
			if !ok {
				t.Errorf("%s is not in economyFields: a new field on a ledger type could carry fiat, a currency, a per-member limit, or a memo — list it only after review", key)
				continue
			}
			if f.Type.Kind() != want {
				t.Errorf("%s has kind %s, want %s", key, f.Type.Kind(), want)
			}
			if want == reflect.Struct && f.Type != timeType && f.Type != policyType {
				t.Errorf("%s is a %s, want time.Time or Policy", key, f.Type)
			}
		}
	}
	for key := range economyFields {
		if !seen[key] {
			t.Errorf("economyFields lists %s, which no ledger type carries — remove it", key)
		}
	}
}

func testEconomyImports(t *testing.T) {
	const canon = "github.com/NTARI-RAND/sohocloud-protocol/canon"
	for name, f := range economySourceByFile(t) {
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if path == canon || !strings.Contains(path, ".") {
				continue // the protocol's canon, or the standard library
			}
			t.Errorf("%s imports %s: the ledger may see only the standard library and canon, so it can never reach the fiat rail, the market, disputes, or the covenant", name, path)
		}
	}
}

// moneyVerb is the vocabulary of buying credit or cashing it out, matched as
// a camel-case word anywhere in an exported name. "Withdraw" is deliberately
// absent: withdrawing a dispute is not a payment.
var moneyVerb = regexp.MustCompile(`(^|[a-z0-9])(Buy|Purchase|Redeem|Redemption|CashOut|Cashout|Payout|PayOut|TopUp|Topup|Deposit|Mint|Burn|Convert|Conversion|ExchangeRate|Peg|Bridge|Fiat)([A-Z0-9]|$)`)

// moneyRoute is the same vocabulary in an HTTP route path, matched as path
// words: routePath splits camelCase and turns "_" into "-" first, so
// "/creditRedeem" and "/cash_out" are caught. Short verbs need a word
// boundary on both sides, so "peg" in "/img.jpeg" or "buy" in "/buyer"
// do not match; long verbs only need one on the left, so "/redeemCredit"
// and "/purchases" do.
var moneyRoute = regexp.MustCompile(`(^|[^a-z])((buy|mint|burn|peg)([^a-z]|$)|(purchase|redeem|redemption|cash-?out|pay-?out|top-?up|deposit|convert|exchange-?rate|bridge))`)

// routeMethod is an HTTP method prefix on a Go 1.22 mux pattern, e.g.
// "PATCH " in "PATCH /v0/redeem".
var routeMethod = regexp.MustCompile(`^[A-Z]+ +`)

var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// routePath returns the path of a route-like string literal, normalized for
// moneyRoute, and whether the literal looks like a route at all.
func routePath(lit string) (string, bool) {
	p := routeMethod.ReplaceAllString(lit, "")
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	p = camelBoundary.ReplaceAllString(p, "$1-$2")
	return strings.ToLower(strings.ReplaceAll(p, "_", "-")), true
}

// fiatTouch names the identifiers that mean a function is handling the fiat
// rail or fiat escrow: market rails, dispute escalations.
var fiatTouch = map[string]bool{
	"Fiat": true, "AcceptFiat": true, "Escalation": true,
	"ActionRefundComplainant": true, "ActionReleaseRespondent": true, "ActionSplit": true,
}

func testL2NoMoneyPath(t *testing.T) {
	root := econModuleRoot(t)
	scanned, creditSites := 0, 0
	econWalkSource(t, root, func(rel string, f *ast.File) {
		scanned++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Name.IsExported() && moneyVerb.MatchString(fn.Name.Name) {
				t.Errorf("%s: exported %s is named like a way to buy credit or cash it out", rel, fn.Name.Name)
			}
			if fn.Body == nil {
				continue
			}
			touchesFiat, movesCredit := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if fiatTouch[x.Name] {
						touchesFiat = true
					}
				case *ast.SelectorExpr:
					if fiatTouch[x.Sel.Name] {
						touchesFiat = true
					}
					if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "economy" && x.Sel.Name == "Spend" {
						movesCredit = true
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING && strings.Contains(x.Value, "/") {
						if v, err := strconv.Unquote(x.Value); err == nil {
							if p, ok := routePath(v); ok && moneyRoute.MatchString(p) {
								t.Errorf("%s: route %q is named like a way to buy credit or cash it out", rel, v)
							}
						}
					}
				}
				return true
			})
			if movesCredit {
				creditSites++
			}
			if touchesFiat && movesCredit {
				t.Errorf("%s: %s both touches the fiat rail and builds an economy.Spend — that is a purchase or redemption path", rel, fn.Name.Name)
			}
		}
	})
	if scanned < 20 {
		t.Fatalf("scanned only %d source files — the scan is not looking at the module", scanned)
	}
	if creditSites == 0 {
		t.Fatal("found no function that builds an economy.Spend; the fiat/credit separation check is not looking at the composition root")
	}
}

func testL2EarnedAtRuntime(t *testing.T) {
	// Escrow: nothing to buy. Every spend is refused and every balance is 0.
	esc := newFixture(t, ModeEscrow, 1000, 0x01, 0x02)
	if err := esc.ledger.Post(esc.spend(esc.members[0], esc.members[1], 10, 1)); !errors.Is(err, ErrCreditDisabled) {
		t.Fatalf("escrow Post = %v, want ErrCreditDisabled", err)
	}
	for _, m := range esc.members {
		if b := esc.ledger.Balance(m.id); b != 0 {
			t.Fatalf("escrow balance %d, want 0: credit exists before it can be earned", b)
		}
	}

	// Credit: a balance rises only as the payee of a spend the PAYER signed.
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02, 0x03)
	payer, payee, outsider := f.members[0], f.members[1], f.members[2]

	// The payee cannot sign its own incoming credit.
	forged := Spend{Platform: f.genesis.Platform, From: payer.id, To: payee.id, Amount: 50,
		ExchangeHash: [32]byte{0x5A}, IssuedAt: time.Unix(1700000000, 0).UTC(), Nonce: 1}
	forged.Sign(payee.priv)
	if err := f.ledger.Post(forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("payee-signed spend = %v, want ErrSignature: credit must be issued by the payer", err)
	}
	// Nor can an outsider (an operator, a processor) sign it.
	forged.Sign(outsider.priv)
	if err := f.ledger.Post(forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("outsider-signed spend = %v, want ErrSignature", err)
	}
	// Nor can anyone pay themselves into a positive balance.
	if err := f.ledger.Post(f.spend(payee, payee, 50, 1)); err == nil {
		t.Fatal("self-transfer admitted")
	}
	if b := f.ledger.Balance(payee.id); b != 0 {
		t.Fatalf("payee balance %d after refused attempts, want 0", b)
	}
	// The honest path: the payer signs.
	if err := f.ledger.Post(f.spend(payer, payee, 50, 1)); err != nil {
		t.Fatalf("payer-signed spend: %v", err)
	}
	if b := f.ledger.Balance(payee.id); b != 50 {
		t.Fatalf("payee balance %d, want 50", b)
	}
}

// TestInvariant_L3_SovereignUnits binds registry ID L3: "no shared unit no
// conversion between communities."
//
//   - the same member key yields unlinkable accounts on different platforms;
//   - a spend signed for one platform never posts on another, cannot be
//     re-pointed at another, and a foreign spend smuggled into a store makes
//     the store refuse to open;
//   - platform identity is fixed at Genesis and lives in no governed field,
//     so no policy change can rebind a ledger to another community;
//   - Amount is a bare count with no denomination, and no conversion,
//     exchange-rate, peg, or bridge API exists anywhere in the module
//     (enforced with L2's scan and field allowlist).
func TestInvariant_L3_SovereignUnits(t *testing.T) {
	t.Run("one key, unlinkable accounts", testL3UnlinkableAccounts)
	t.Run("a spend is bound to one platform", testL3SpendBound)
	t.Run("platform identity is not governable", testL3PlatformFixed)
	t.Run("no conversion surface", testL3NoConversion)
}

func testL3UnlinkableAccounts(t *testing.T) {
	_, pub := seedKey(0x31)
	platforms := []string{"cloudy", "agrinet", "lighthouse", "cloudy-2"}
	seen := map[AccountID]string{}
	for _, p := range platforms {
		id := AccountIDFor(p, pub)
		if prev, dup := seen[id]; dup {
			t.Fatalf("one key yields the same account on %q and %q: the two communities share a unit of identity", prev, p)
		}
		seen[id] = p
	}
}

func testL3SpendBound(t *testing.T) {
	a := newFixture(t, ModeCredit, 100, 0x01, 0x02)
	// A second community with the SAME member keys registered.
	bGen := a.genesis
	bGen.Platform = "cloudy-other"
	bDir := mapDirectory{}
	var bMembers []member
	for _, seed := range []byte{0x01, 0x02} {
		m := newTestMember(bGen.Platform, seed)
		bMembers = append(bMembers, m)
		bDir[m.id] = m.pub
	}
	bStore := NewMemStore()
	bLedger, err := Open(bGen, bDir, bStore)
	if err != nil {
		t.Fatalf("Open B: %v", err)
	}

	// A valid spend on A...
	sA := a.spend(a.members[0], a.members[1], 10, 1)
	if err := a.ledger.Post(sA); err != nil {
		t.Fatalf("Post on A: %v", err)
	}
	// ...never posts on B, as-is or re-pointed at B's accounts and platform.
	if err := bLedger.Post(sA); err == nil {
		t.Error("A's spend posted on B")
	}
	moved := sA
	moved.Platform, moved.From, moved.To = bGen.Platform, bMembers[0].id, bMembers[1].id
	if err := bLedger.Post(moved); !errors.Is(err, ErrSignature) {
		t.Errorf("A's signature re-pointed at B = %v, want ErrSignature", err)
	}
	for _, m := range bMembers {
		if bal := bLedger.Balance(m.id); bal != 0 {
			t.Errorf("B balance %d after A's trade, want 0: value crossed communities", bal)
		}
	}

	// A foreign spend written straight into B's store makes B refuse to open.
	if err := bStore.Append(0, sA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := Open(bGen, bDir, bStore); !errors.Is(err, ErrTampered) {
		t.Errorf("Open over a store holding A's spend = %v, want ErrTampered", err)
	}
}

func testL3PlatformFixed(t *testing.T) {
	// Policy — the only governed configuration — has no platform field.
	pol := reflect.TypeOf(Policy{})
	for i := 0; i < pol.NumField(); i++ {
		if pol.Field(i).Type.Kind() == reflect.String && pol.Field(i).Name != "Mode" {
			t.Errorf("Policy.%s is a string: platform identity must not be governable", pol.Field(i).Name)
		}
	}
	// A quorum-signed change for another platform is refused, and after a
	// valid change the ledger is still bound to its own platform.
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02)
	other := f.change(Policy{Mode: ModeCredit, DebitCap: 200}, 1, 2)
	other.Platform = "cloudy-other"
	other.Sigs = nil
	other.Sign(f.stewards[0])
	other.Sign(f.stewards[1])
	if err := f.ledger.Enact(other); err == nil {
		t.Error("a policy change for another platform was enacted")
	}
	if err := f.ledger.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 200}, 1, 2)); err != nil {
		t.Fatalf("Enact: %v", err)
	}
	s := f.spend(f.members[0], f.members[1], 10, 1)
	s.Platform = "cloudy-other"
	s.Sign(f.members[0].priv)
	if err := f.ledger.Post(s); err == nil {
		t.Error("after a policy change the ledger accepted another platform's spend")
	}
}

func testL3NoConversion(t *testing.T) {
	// Amount is a bare count of this platform's own unit: no denomination.
	if k := reflect.TypeOf(Amount(0)).Kind(); k != reflect.Uint64 {
		t.Errorf("Amount kind %s, want uint64: a unit must not carry a denomination", k)
	}
	// The conversion vocabulary (Convert, ExchangeRate, Peg, Bridge, Fiat) is
	// enforced module-wide by testL2NoMoneyPath, and every ledger field by
	// testEconomyFieldAllowlist; run them here so L3 fails on its own.
	testL2NoMoneyPath(t)
	testEconomyFieldAllowlist(t)
}

// TestInvariant_L9_OperatorSetUniformLimit binds registry ID L9: "one
// uniform limit per operator community, set by that operator; never
// per-member, never derived from reputation."
//
//   - one number: Policy carries exactly one limit and nothing per-account;
//   - uniform: members and operator-held keys hit exactly the same floor,
//     before and after the limit changes;
//   - set by the operator's governance: only a quorum of the Genesis
//     stewards can move it; a member, an outsider, or a short quorum cannot;
//   - never from reputation: the ledger cannot import the covenant, and no
//     function anywhere in the module that sets the limit reads a member's
//     standing. Residual, named rather than hidden: the source scan is
//     per-function, so a limit computed from standing in one function and
//     passed into another that sets it would not be seen; the import wall
//     and the steward quorum are the structural checks behind it.
func TestInvariant_L9_OperatorSetUniformLimit(t *testing.T) {
	t.Run("one number, nothing per member", testL9OneNumber)
	t.Run("every account hits the same floor", testL9Uniform)
	t.Run("only the stewards' quorum moves it", testL9StewardsOnly)
	t.Run("never derived from reputation", testL9NotFromReputation)
}

func testL9OneNumber(t *testing.T) {
	pol := reflect.TypeOf(Policy{})
	var limits []string
	for i := 0; i < pol.NumField(); i++ {
		f := pol.Field(i)
		switch f.Type.Kind() {
		case reflect.Map, reflect.Slice, reflect.Array, reflect.Func, reflect.Interface, reflect.Ptr, reflect.Struct:
			t.Errorf("Policy.%s is a %s: a per-member or computed limit hides in a field like this", f.Name, f.Type.Kind())
		}
		if f.Type == reflect.TypeOf(Amount(0)) {
			limits = append(limits, f.Name)
		}
	}
	if len(limits) != 1 || limits[0] != "DebitCap" {
		t.Errorf("Policy limit fields = %v, want exactly [DebitCap]", limits)
	}
	// Post's limit check reads only the policy, never the account: the
	// allowlisted API (testL2LedgerAPI) has no per-account setter.
	testL2LedgerAPI(t)
}

func testL9Uniform(t *testing.T) {
	// members[3] plays an operator-held key: it is just another account and
	// gets no deeper well.
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02, 0x03, 0x04)
	sink := f.members[0]
	payers := f.members[1:]
	floor := func(cap Amount, nonce uint64) {
		t.Helper()
		for _, p := range payers {
			need := int64(cap) + int64(f.ledger.Balance(p.id))
			if need > 0 {
				if err := f.ledger.Post(f.spend(p, sink, Amount(need), nonce)); err != nil {
					t.Fatalf("spend to the floor -%d: %v", cap, err)
				}
			}
			if got := f.ledger.Balance(p.id); got != Balance(-int64(cap)) {
				t.Fatalf("balance %d, want exactly -%d", got, cap)
			}
			if err := f.ledger.Post(f.spend(p, sink, 1, nonce+1)); !errors.Is(err, ErrLimit) {
				t.Fatalf("one unit past -%d = %v, want ErrLimit for every account alike", cap, err)
			}
		}
	}
	floor(100, 1)
	if err := f.ledger.Enact(f.change(Policy{Mode: ModeCredit, DebitCap: 250}, 1, 2)); err != nil {
		t.Fatalf("Enact: %v", err)
	}
	floor(250, 3)
}

func testL9StewardsOnly(t *testing.T) {
	f := newFixture(t, ModeCredit, 100, 0x01, 0x02)
	raise := Policy{Mode: ModeCredit, DebitCap: 10000}

	// A short quorum (1 of a 2-of-3) is refused.
	if err := f.ledger.Enact(f.change(raise, 1, 1)); !errors.Is(err, ErrQuorum) {
		t.Errorf("1 steward of a 2-of-3 quorum = %v, want ErrQuorum", err)
	}
	// Members' signatures count for nothing, however many.
	c := PolicyChange{Platform: f.genesis.Platform, Policy: raise, Version: 1, At: time.Unix(1700000100, 0).UTC()}
	for _, m := range f.members {
		c.Sign(m.priv)
	}
	if err := f.ledger.Enact(c); !errors.Is(err, ErrQuorum) {
		t.Errorf("members-only change = %v, want ErrQuorum", err)
	}
	// One steward signing twice is still one.
	c = PolicyChange{Platform: f.genesis.Platform, Policy: raise, Version: 1, At: time.Unix(1700000100, 0).UTC()}
	c.Sign(f.stewards[0])
	c.Sign(f.stewards[0])
	if err := f.ledger.Enact(c); !errors.Is(err, ErrQuorum) {
		t.Errorf("duplicate steward signature = %v, want ErrQuorum", err)
	}
	if got := f.ledger.Policy().DebitCap; got != 100 {
		t.Fatalf("limit moved to %d without the stewards' quorum", got)
	}
	// The stewards' quorum moves it, for everyone at once.
	if err := f.ledger.Enact(f.change(raise, 1, 2)); err != nil {
		t.Fatalf("quorum Enact: %v", err)
	}
	if got := f.ledger.Policy().DebitCap; got != 10000 {
		t.Fatalf("limit = %d after quorum, want 10000", got)
	}
}

// reputationRead names the covenant read surface. A selector on the
// covenant package with one of these names, or a call to one of the
// distinctive standing readers (Standing, Relation, Overall, Harm) in a file
// that imports the covenant, means the function is reading a member's
// standing.
var reputationRead = map[string]bool{
	"Standing": true, "Relation": true, "Overall": true, "Harm": true,
	"Count": true, "Total": true, "Distribution": true, "RelationStanding": true,
}

var standingReader = map[string]bool{"Standing": true, "Relation": true, "Overall": true, "Harm": true}

func testL9NotFromReputation(t *testing.T) {
	// The ledger cannot see the covenant at all.
	testEconomyImports(t)

	// Anywhere the limit is set — an economy.Policy is built, or a DebitCap
	// is assigned — the same function must not read covenant standing.
	root := econModuleRoot(t)
	setSites := map[string]bool{}
	econWalkSource(t, root, func(rel string, f *ast.File) {
		covName := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); strings.HasSuffix(p, "/internal/covenant") {
				covName = "covenant"
				if imp.Name != nil {
					covName = imp.Name.Name
				}
			}
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			setsLimit, readsStanding := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					// Building an economy.Policy or PolicyChange sets the
					// limit; a JSON response that merely echoes DebitCap
					// does not, and is not counted.
					if sel, ok := x.Type.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Policy" || sel.Sel.Name == "PolicyChange") {
						if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "economy" {
							setsLimit = true
						}
					}
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "DebitCap" {
							setsLimit = true
						}
					}
				case *ast.SelectorExpr:
					if covName == "" {
						break
					}
					if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == covName && reputationRead[x.Sel.Name] {
						readsStanding = true
					}
					if standingReader[x.Sel.Name] {
						readsStanding = true
					}
				}
				return true
			})
			if setsLimit && strings.HasPrefix(rel, filepath.Join("internal", "economy")) {
				continue // the ledger's own validation, which cannot import the covenant
			}
			if setsLimit {
				setSites[rel] = true
			}
			if setsLimit && readsStanding {
				t.Errorf("%s: %s sets the credit limit and reads covenant standing: the limit must never be derived from reputation", rel, fn.Name.Name)
			}
		}
	})
	// Both composition roots open a ledger with a Policy; if either drops
	// out of view the check has gone blind, so pin them.
	for _, root := range []string{
		filepath.Join("internal", "consumerapi", "server.go"),
		filepath.Join("cmd", "cloudy", "main.go"),
	} {
		if !setSites[root] {
			t.Errorf("%s sets the credit limit but the check did not see it; the scan is not looking at the composition roots", root)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// economySourceByFile parses this package's shipped (non-test) files.
func economySourceByFile(t *testing.T) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		out[n] = f
	}
	if len(out) < 3 {
		t.Fatalf("parsed only %d economy source files", len(out))
	}
	return out
}

func economySource(t *testing.T) []*ast.File {
	t.Helper()
	var out []*ast.File
	for _, f := range economySourceByFile(t) {
		out = append(out, f)
	}
	return out
}

func econModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the economy package")
		}
		dir = parent
	}
}

func econWalkSource(t *testing.T, root string, fn func(rel string, f *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if n := info.Name(); n == ".git" || n == "vendor" || n == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		fn(rel, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

func econReceiverName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return econReceiverName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return econReceiverName(x.X)
	}
	return ""
}
