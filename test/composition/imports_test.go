// imports_test.go is the import-graph tripwire for the JFA layering rule:
// internal/economy, internal/covenant, internal/record, and internal/dispute
// never import each other (or anything else in this module), and only the two
// composition roots — cmd/cloudy and test/composition — may ever see more than
// one of them. The check is a pure go/parser + filepath.Walk scan (no
// subprocess, no go/build): every .go file in the module is parsed in
// ImportsOnly mode and grouped by directory.
package composition_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/NTARI-RAND/Cloudy"

// jfaImportPaths are the four JFA member-economy packages the layering rule
// is about.
var jfaImportPaths = []string{
	modulePath + "/internal/economy",
	modulePath + "/internal/covenant",
	modulePath + "/internal/record",
	modulePath + "/internal/dispute",
}

// moduleRoot walks up from the test's working directory (the package dir) to
// the directory containing go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test directory")
		}
		dir = parent
	}
}

func TestImportGraph(t *testing.T) {
	root := moduleRoot(t)

	// imports[relDir] = union of import paths across every .go file in that
	// directory (package sources and test files alike — a test-only import of
	// a second JFA package would be just as much a layering breach).
	imports := make(map[string]map[string]bool)
	fset := token.NewFileSet()
	parsed := 0
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if info.IsDir() {
			// Skip hidden and underscore-prefixed dirs (including transient
			// .gotmp-* build dirs), vendored code, and testdata fixtures;
			// everything else in the module tree is scanned.
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		parsed++
		rel, rerr := filepath.Rel(root, filepath.Dir(path))
		if rerr != nil {
			return rerr
		}
		dir := filepath.ToSlash(rel)
		set := imports[dir]
		if set == nil {
			set = make(map[string]bool)
			imports[dir] = set
		}
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				return uerr
			}
			set[p] = true
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking module: %v", walkErr)
	}
	if parsed == 0 {
		t.Fatal("parsed zero .go files; the walk itself is broken")
	}

	// (a) The four JFA packages import NO package from this module at all —
	// not each other, not coord, nothing under github.com/NTARI-RAND/Cloudy.
	for _, jfaDir := range []string{"internal/economy", "internal/covenant", "internal/record", "internal/dispute"} {
		set, ok := imports[jfaDir]
		if !ok {
			t.Fatalf("no .go files found under %s; the walk missed a JFA package", jfaDir)
		}
		for imp := range set {
			// A directory's external test package (package foo_test) imports its
			// own package by module path; that is a self-edge, not a layering
			// breach — only imports of OTHER module packages violate the graph.
			if imp == modulePath+"/"+jfaDir {
				continue
			}
			if imp == modulePath || strings.HasPrefix(imp, modulePath+"/") {
				t.Errorf("%s imports %q: JFA packages must not import ANY other %s package", jfaDir, imp, modulePath)
			}
		}
	}

	// (b) Only the composition roots may import more than one JFA package.
	// internal/consumerapi is the member-facing composition root by design
	// (Phase-1 design §2: cloudyd = composition root + consumer JSON API; the
	// cmd/cloudyd main stays a thin flag-parsing shell over it, importing no
	// JFA package itself). Everything else composes nothing.
	allowedRoots := map[string]bool{"cmd/cloudy": true, "internal/consumerapi": true, "test/composition": true}
	var roots []string
	for dir, set := range imports {
		n := 0
		for _, jfa := range jfaImportPaths {
			if set[jfa] {
				n++
			}
		}
		if n > 1 {
			roots = append(roots, dir)
			if !allowedRoots[dir] {
				t.Errorf("%s imports %d of the four JFA packages; only cmd/cloudy and test/composition may compose them", dir, n)
			}
		}
	}

	// Positive control proving the scan has teeth: every known composition
	// root must be found, each importing all four JFA packages — if the
	// walk or the parse ever silently skipped them, this fails rather than
	// the tripwire going green on an empty graph.
	sort.Strings(roots)
	want := []string{"cmd/cloudy", "internal/consumerapi", "test/composition"}
	if len(roots) != len(want) {
		t.Fatalf("composition roots found: %v, want exactly %v", roots, want)
	}
	for i := range want {
		if roots[i] != want[i] {
			t.Fatalf("composition roots found: %v, want exactly %v", roots, want)
		}
	}
	for _, dir := range want {
		for _, jfa := range jfaImportPaths {
			if !imports[dir][jfa] {
				t.Errorf("known composition root %s does not import %s; the scan is not seeing real imports", dir, jfa)
			}
		}
	}
}
