package market

import (
	"crypto/ed25519"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testPlatform = "cloudy-test"

func mustKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func spec(b byte) SpecRef {
	var s SpecRef
	for i := range s {
		s[i] = b
	}
	return s
}

func signedListing(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, cat Category, s SpecRef, rails AcceptedRails) Listing {
	t.Helper()
	l, err := NewListing(testPlatform, pub, cat, s, rails, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestListingRoundTripAndTamper(t *testing.T) {
	pub, priv := mustKey(t, 1)
	l := signedListing(t, pub, priv, CategoryComputer, spec(7), AcceptedRails{Fiat: true})
	if !l.Verify() {
		t.Fatal("valid listing rejected")
	}
	id := l.ID()
	l.Category = CategorySmartTV // mutate a signed field
	if l.Verify() {
		t.Fatal("tampered listing verified")
	}
	if l.ID() == id {
		t.Fatal("ID did not change when a signed field changed")
	}
}

func TestListingRejectsBadInputs(t *testing.T) {
	pub, _ := mustKey(t, 1)
	// Out-of-allowlist category ("no tomatoes").
	if _, err := NewListing(testPlatform, pub, Category("tomato"), spec(1), AcceptedRails{Fiat: true}, time.Unix(1, 0)); err == nil {
		t.Fatal("out-of-allowlist category must be rejected")
	}
	// Empty rails.
	if _, err := NewListing(testPlatform, pub, CategoryComputer, spec(1), AcceptedRails{}, time.Unix(1, 0)); err == nil {
		t.Fatal("a listing with no accepted rail must be rejected")
	}
	// Zero spec ref (must point at an anchored product-spec claim).
	if _, err := NewListing(testPlatform, pub, CategoryComputer, SpecRef{}, AcceptedRails{Fiat: true}, time.Unix(1, 0)); err == nil {
		t.Fatal("a listing with no product-spec claim must be rejected")
	}
	// Cross-platform rejected at catalog insert.
	other, err := NewListing("other", pub, CategoryComputer, spec(1), AcceptedRails{Fiat: true}, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	_, opriv := mustKey(t, 1)
	_ = other.Sign(opriv)
	cat, _ := NewCatalog(testPlatform)
	if _, err := cat.AddListing(other); !errors.Is(err, ErrWrongPlatform) {
		t.Fatalf("cross-platform listing: got %v, want ErrWrongPlatform", err)
	}
}

func TestCatalogAddDedupAndCategory(t *testing.T) {
	cat, _ := NewCatalog(testPlatform)
	pubA, privA := mustKey(t, 1)
	pubB, privB := mustKey(t, 2)

	comp := signedListing(t, pubA, privA, CategoryComputer, spec(10), AcceptedRails{Fiat: true, MemberCredit: true})
	compID, err := cat.AddListing(comp)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := cat.AddListing(comp); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("re-add: got %v, want ErrDuplicate", err)
	}
	tv := signedListing(t, pubB, privB, CategorySmartTV, spec(20), AcceptedRails{Fiat: true})
	if _, err := cat.AddListing(tv); err != nil {
		t.Fatal(err)
	}
	comps := cat.ByCategory(CategoryComputer)
	if len(comps) != 1 || comps[0] != compID {
		t.Fatalf("ByCategory(computer) = %v, want [%x]", comps, compID)
	}
	if len(cat.ByCategory(CategoryNASStorage)) != 0 {
		t.Fatal("empty category should return no listings")
	}
}

func TestRecordSaleAndProvenance(t *testing.T) {
	cat, _ := NewCatalog(testPlatform)
	pub, priv := mustKey(t, 1)
	l := signedListing(t, pub, priv, CategoryComputer, spec(10), AcceptedRails{MemberCredit: true})
	id, _ := cat.AddListing(l)

	ex1 := ExchangeRef(spec(101))
	ex2 := ExchangeRef(spec(102))
	if err := cat.RecordSale(id, ex1, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := cat.RecordSale(id, ex2, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if err := cat.RecordSale(id, ex1, time.Unix(4, 0)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("re-record same exchange: got %v, want ErrDuplicate", err)
	}
	if err := cat.RecordSale(ListingID(spec(200)), ex1, time.Unix(5, 0)); !errors.Is(err, ErrUnknownListing) {
		t.Fatalf("sale for unknown listing: got %v, want ErrUnknownListing", err)
	}
	sales := cat.SalesOf(id)
	if len(sales) != 2 || sales[0] != ex1 || sales[1] != ex2 {
		t.Fatalf("SalesOf = %v, want [ex1 ex2] in order (provenance)", sales)
	}
}

func TestOpenLogReplayHeadAndTamper(t *testing.T) {
	cat, _ := NewCatalog(testPlatform)
	pub, priv := mustKey(t, 1)
	l := signedListing(t, pub, priv, CategoryComputer, spec(10), AcceptedRails{Fiat: true})
	id, _ := cat.AddListing(l)
	_ = cat.RecordSale(id, ExchangeRef(spec(101)), time.Unix(2, 0))

	rebuilt, err := OpenLog(testPlatform, cat.Log())
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if rebuilt.Head() != cat.Head() {
		t.Fatal("replayed head differs — chain is not deterministic")
	}
	if cat.Head() == (Hash{}) {
		t.Fatal("non-empty catalog has a zero head")
	}

	// Tamper a listing signature → replay fails.
	log := cat.Log()
	log[0].Listing.Signature[0] ^= 1
	if _, err := OpenLog(testPlatform, log); err == nil {
		t.Fatal("OpenLog accepted a tampered listing")
	}

	// Reorder: a sale before its listing → replay fails closed.
	reordered := []Item{{Sale: &Sale{Listing: id, Exchange: ExchangeRef(spec(101)), RecordedAt: time.Unix(2, 0)}}}
	if _, err := OpenLog(testPlatform, reordered); !errors.Is(err, ErrUnknownListing) {
		t.Fatalf("reordered log: got %v, want ErrUnknownListing", err)
	}
}

// noPlacementPattern matches names that would smell like paid placement, a
// promoted/sponsored listing, a ranking, or a truth-certification flag — all
// off-architecture (refuse-list + no-truth-authority). It excludes ed25519
// "Verify" (signature) and the legitimate category/rails/sales vocabulary.
var noPlacementPattern = regexp.MustCompile(`(?i)(promot|sponsor|boost|featured|paidplacement|rank|certif|verified(listing|product)|official|endorse)`)

func TestNoPaidPlacementTripwire(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(&Catalog{}),
		reflect.TypeOf(&Listing{}),
		reflect.TypeOf(&Sale{}),
		reflect.TypeOf(&AcceptedRails{}),
		reflect.TypeOf(new(Category)),
	}
	for _, typ := range types {
		for i := 0; i < typ.NumMethod(); i++ {
			if name := typ.Method(i).Name; noPlacementPattern.MatchString(name) {
				t.Errorf("%s has exported method %q — paid placement, promotion, ranking, and truth-certification are off-architecture", typ, name)
			}
		}
	}
	// go/ast scan of shipped source for the same.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			if noPlacementPattern.MatchString(fn.Name.Name) {
				t.Errorf("%s declares exported func/method %q — no paid placement / promotion / ranking / certification", name, fn.Name.Name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no package source files — the tripwire is not looking at the package")
	}
}
