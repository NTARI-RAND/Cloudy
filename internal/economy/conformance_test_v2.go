package covenant

// JFA conformance bindings for the covenant layer.
//
// Test names carry the Janus registry ID they bind (jfa-conformance-suite.py
// in NTARI-RAND/Janus), so a CI log parser can map a PASS/FAIL back to the
// invariant: TestInvariant_<ID>_<Name>, with any "-" in the ID written "_".

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestInvariant_L8_NoScalarAggregation binds registry ID L8: "full
// distribution carried; no scalar score anywhere."
//
// The package-local tripwires (TestNoCollapseTripwire,
// TestNoCollapseFunctionTripwire, TestStandingNotSerializable) hold the line
// inside internal/covenant. This binding adds the two things L8 says that
// those do not:
//
//   - "full distribution carried": two members a mean cannot tell apart are
//     told apart by Standing, level by level, and nothing is lost.
//   - "anywhere": the whole module, not just this package, exposes no scalar
//     summary of reputation.
func TestInvariant_L8_NoScalarAggregation(t *testing.T) {
	t.Run("full distribution carried", testL8FullDistribution)
	t.Run("no scalar anywhere in the module", testL8NoScalarInModule)
}

// testL8FullDistribution records two subjects whose verdicts have the SAME
// arithmetic mean (+2) but different shapes, and requires Standing to keep
// every level's count, so the one who caused harm is never averaged into the
// same number as the one who never did.
func testL8FullDistribution(t *testing.T) {
	steady, steadyPub, _ := testMember(0x30) // 2, 2, 2, 2        mean 2
	harmed, harmedPub, _ := testMember(0x40) // -1, 4, 4, 1       mean 2

	dir := dirMap{steady: steadyPub, harmed: harmedPub}
	seals := sealSet{}
	b := testBook(t, dir, seals, NewMemStore())

	cats := []string{"reliability", "usability", "performance", "support"}
	type verdict struct {
		subject MemberID
		level   Level
	}
	var verdicts []verdict
	for _, l := range []Level{LevelBasicSatisfaction, LevelBasicSatisfaction, LevelBasicSatisfaction, LevelBasicSatisfaction} {
		verdicts = append(verdicts, verdict{steady, l})
	}
	for _, l := range []Level{LevelNoTrust, LevelDelight, LevelDelight, LevelBasicPromise} {
		verdicts = append(verdicts, verdict{harmed, l})
	}

	for i, v := range verdicts {
		assessor, pub, priv := testMember(byte(0x90 + i))
		dir[assessor] = pub
		ex := ref(byte(0x40 + i))
		seals.seal(ex, assessor, v.subject)
		a := Assessment{
			Assessor: assessor,
			Subject:  v.subject,
			Exchange: ex,
			Relation: RelationTrade,
			Category: cats[i%len(cats)],
			Level:    v.level,
			IssuedAt: time.Unix(1700001000+int64(i), 0).UTC(),
		}
		if v.level == LevelNoTrust {
			a.CommentHash = commentHash(byte(0xD0 + i))
		}
		a.Sign(priv)
		if err := b.Record(a); err != nil {
			t.Fatalf("Record #%d = %v", i, err)
		}
	}

	// Guard the premise: a mean would make these two identical.
	mean := func(subject MemberID) float64 {
		var sum, n int
		for _, v := range verdicts {
			if v.subject == subject {
				sum += int(v.level)
				n++
			}
		}
		return float64(sum) / float64(n)
	}
	if mean(steady) != mean(harmed) {
		t.Fatalf("fixture broken: means %v and %v differ; the test must pit equal means against unequal shapes", mean(steady), mean(harmed))
	}

	want := map[MemberID]map[Level]int{
		steady: {LevelBasicSatisfaction: 4},
		harmed: {LevelNoTrust: 1, LevelDelight: 2, LevelBasicPromise: 1},
	}
	got := map[MemberID]Distribution{}
	for subject, wantCounts := range want {
		s, err := b.Standing(subject)
		if err != nil {
			t.Fatalf("Standing = %v", err)
		}
		d := s.Relation(RelationTrade).Overall()
		got[subject] = d
		counted := 0
		for _, l := range Levels() {
			if d.Count(l) != wantCounts[l] {
				t.Errorf("count at %q = %d, want %d", l, d.Count(l), wantCounts[l])
			}
			counted += d.Count(l)
		}
		if counted != d.Total() || d.Total() != 4 {
			t.Errorf("per-level counts sum to %d, Total = %d, want both 4: the distribution must be lossless", counted, d.Total())
		}
		if h := s.Relation(RelationTrade).Harm(); h != wantCounts[LevelNoTrust] {
			t.Errorf("Harm = %d, want %d: the breach must never be diluted by volume", h, wantCounts[LevelNoTrust])
		}
	}

	differ := false
	for _, l := range Levels() {
		if got[steady].Count(l) != got[harmed].Count(l) {
			differ = true
		}
	}
	if !differ {
		t.Fatal("Standing cannot tell apart two members with different shapes: the distribution has been collapsed")
	}
}

// collapseName is the vocabulary of a scalar reputation summary. It is
// narrower than the package tripwire's collapsePattern because it scans the
// whole module, where "sum" (checksum) and "weight" (techtree citation
// breakdown, a struct of counts) are legitimate.
var collapseName = regexp.MustCompile(`(?i)(mean|avg|average|score|median|percentile|rank)`)

// collapseJSON catches a scalar leaking onto the wire through a struct tag.
var collapseJSON = regexp.MustCompile(`json:"(?i:[a-z_]*(mean|avg|average|score|median|percentile|rank|rating)[a-z_]*)[",]`)

// reputationDirs are the packages that hold or serve member reputation; any
// floating-point field there is a scalar waiting to happen.
var reputationDirs = map[string]bool{
	filepath.Join("internal", "covenant"):    true,
	filepath.Join("internal", "consumerapi"): true,
}

// testL8NoScalarInModule parses every shipped Go file in the module and
// fails on: an exported function or method named like a collapse; an
// exported function or method returning a float; a struct tag that puts a
// score-like field on the wire; or a float field in a reputation package.
func testL8NoScalarInModule(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	scanned := 0
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
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		scanned++
		inReputation := reputationDirs[filepath.Dir(rel)]

		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if !x.Name.IsExported() {
					return true
				}
				if collapseName.MatchString(x.Name.Name) {
					t.Errorf("%s: exported %q is named like a scalar reputation summary", rel, x.Name.Name)
				}
				if x.Type.Results != nil {
					for _, r := range x.Type.Results.List {
						if isFloat(r.Type) {
							t.Errorf("%s: exported %q returns a float; a scalar is one step from a score", rel, x.Name.Name)
						}
					}
				}
			case *ast.StructType:
				for _, fld := range x.Fields.List {
					line := fset.Position(fld.Pos()).Line
					if fld.Tag != nil && collapseJSON.MatchString(fld.Tag.Value) {
						t.Errorf("%s:%d: struct tag %s puts a score-like field on the wire", rel, line, fld.Tag.Value)
					}
					if inReputation && isFloat(fld.Type) {
						t.Errorf("%s:%d: float field in a reputation package", rel, line)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d source files from %s — the scan is not looking at the module", scanned, root)
	}
}

func isFloat(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && (id.Name == "float32" || id.Name == "float64")
}

// moduleRoot walks up from the package directory to the directory holding
// go.mod.
func moduleRoot(t *testing.T) string {
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
			t.Fatal("no go.mod above the covenant package")
		}
		dir = parent
	}
}
