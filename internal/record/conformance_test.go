package record

// JFA conformance bindings for the record layer.
//
// Test names carry the Janus registry ID they bind (jfa-conformance-suite.py
// in NTARI-RAND/Janus), so a CI log parser can map a PASS/FAIL back to the
// invariant: TestInvariant_<ID>_<Name>, with any "-" in the ID written "_".

import (
	"crypto/ed25519"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestInvariant_L6_AppendOnly binds registry ID L6: "no update-in-place, no
// delete; dismissal is annotation."
//
// The dismissal half is bound in internal/covenant by
// TestAnswersCloseTheSymmetryBreach (an answer annotates; the harm it answers
// still counts). This binding covers the record half:
//
//   - a correction is a NEW entry; the corrected entry stays at its position,
//     byte for byte, and every proof issued before the correction still
//     verifies;
//   - an in-place rewrite of history, done by going around the Log straight
//     to storage, is caught by the consistency proof a member already holds;
//   - no store, log, ledger, or book anywhere in the module exposes an
//     update or delete verb.
func TestInvariant_L6_AppendOnly(t *testing.T) {
	t.Run("correction appends, never replaces", testL6CorrectionAppends)
	t.Run("in-place rewrite is detectable", testL6RewriteDetected)
	t.Run("no mutating verbs in the module", testL6NoMutatingVerbs)
}

func testL6CorrectionAppends(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	l, ms, entries := buildLog(t, op, a, b, 3)

	cp3 := l.Checkpoint(testInstant)
	cp3.Sign(op.priv)
	before := make([]Proof, len(entries))
	for i := range entries {
		p, err := l.Prove(uint64(i))
		if err != nil {
			t.Fatalf("Prove(%d): %v", i, err)
		}
		before[i] = p
	}

	// Correct entry 1 the only way the record allows: a new, dual-sealed
	// entry that references it.
	fix := sealedEntry(t, LogID(op.pub), a, b, contentN(0xF1), entries[1].ID(), testInstant.Add(time.Hour))
	seq, err := l.Append(fix)
	if err != nil {
		t.Fatalf("Append(correction): %v", err)
	}
	if seq != 3 {
		t.Fatalf("correction landed at %d, want 3 (the end of the log)", seq)
	}
	if n, _ := ms.Len(); n != 4 {
		t.Fatalf("store holds %d entries after a correction, want 4: nothing may be removed", n)
	}

	// Every original entry is still there, unchanged.
	for i, want := range entries {
		got, err := ms.At(uint64(i))
		if err != nil {
			t.Fatalf("At(%d): %v", i, err)
		}
		if got.ID() != want.ID() {
			t.Fatalf("entry %d changed after a correction: the record must never edit in place", i)
		}
	}
	got, _ := ms.At(3)
	if got.Corrects != entries[1].ID() {
		t.Fatal("the correction does not reference the entry it corrects")
	}

	// Every proof issued before the correction still verifies against the
	// checkpoint it was issued with, and the new head provably extends it.
	for i, e := range entries {
		if !VerifyInclusion(e, before[i], cp3, op.pub) {
			t.Fatalf("pre-correction proof for entry %d no longer verifies", i)
		}
	}
	cp4 := l.Checkpoint(testInstant.Add(2 * time.Hour))
	cp4.Sign(op.priv)
	proof, err := l.ProveConsistency(3)
	if err != nil {
		t.Fatalf("ProveConsistency: %v", err)
	}
	if !VerifyConsistency(cp3, cp4, proof, op.pub) {
		t.Fatal("the corrected log does not provably extend the log before the correction")
	}
}

// sliceStore is a Store whose backing slice a test can rewrite directly: it
// plays an operator who goes around Log to edit history on disk.
type sliceStore struct{ entries []Entry }

func (s *sliceStore) Append(e Entry) error { s.entries = append(s.entries, e); return nil }
func (s *sliceStore) Len() (uint64, error) { return uint64(len(s.entries)), nil }
func (s *sliceStore) At(seq uint64) (Entry, error) {
	if seq >= uint64(len(s.entries)) {
		return Entry{}, os.ErrNotExist
	}
	return s.entries[seq], nil
}

func testL6RewriteDetected(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)

	st := &sliceStore{}
	l, err := OpenLog(op.pub, st)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := l.Append(sealedEntry(t, id, a, b, contentN(byte(i)), Hash{}, testInstant)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	// A member holds this checkpoint from before the rewrite.
	held := l.Checkpoint(testInstant)
	held.Sign(op.priv)

	// The operator swaps entry 2 for a different, validly sealed one — the
	// strongest in-place edit available, since it passes every per-entry
	// check — and keeps going.
	st.entries[2] = sealedEntry(t, id, a, b, contentN(0xEE), Hash{}, testInstant)
	l2, err := OpenLog(op.pub, st)
	if err != nil {
		t.Fatalf("OpenLog after rewrite: %v", err)
	}
	if _, err := l2.Append(sealedEntry(t, id, a, b, contentN(0x10), Hash{}, testInstant)); err != nil {
		t.Fatalf("Append after rewrite: %v", err)
	}
	newer := l2.Checkpoint(testInstant.Add(time.Hour))
	newer.Sign(op.priv)
	proof, err := l2.ProveConsistency(held.Size)
	if err != nil {
		t.Fatalf("ProveConsistency: %v", err)
	}
	if VerifyConsistency(held, newer, proof, op.pub) {
		t.Fatal("a rewritten history passed consistency against a checkpoint taken before the rewrite: in-place edits must be detectable")
	}
}

// mutatingVerb is the vocabulary of update-in-place and delete.
var mutatingVerb = regexp.MustCompile(`^(Update|Delete|Remove|Edit|Replace|Overwrite|Truncate|Set|Erase|Drop|Clear|Rewrite|Amend|Modify|Purge|Reset)`)

// persistentType names the types that hold the record of what happened:
// stores, logs, ledgers, and books, in every layer.
var persistentType = regexp.MustCompile(`(Store|Log|Ledger|Book)$`)

// testL6NoMutatingVerbs scans every shipped Go file in the module. A method
// on, or an interface named like, a store/log/ledger/book must not start
// with an update or delete verb. Locker.Erase is the one sanctioned erasure
// and is out of scope by construction: Locker is the member-local store,
// type-disjoint from every log, and never enters a chain.
func testL6NoMutatingVerbs(t *testing.T) {
	root := moduleRoot(t)
	scanned := 0
	walkSource(t, root, func(rel string, f *ast.File) {
		scanned++
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 || !d.Name.IsExported() {
					continue
				}
				recv := receiverName(d.Recv.List[0].Type)
				if persistentType.MatchString(recv) && mutatingVerb.MatchString(d.Name.Name) {
					t.Errorf("%s: %s.%s is an update or delete verb on a record-holding type", rel, recv, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || !persistentType.MatchString(ts.Name.Name) {
						continue
					}
					it, ok := ts.Type.(*ast.InterfaceType)
					if !ok {
						continue
					}
					for _, m := range it.Methods.List {
						for _, n := range m.Names {
							if mutatingVerb.MatchString(n.Name) {
								t.Errorf("%s: interface %s declares %s, an update or delete verb", rel, ts.Name.Name, n.Name)
							}
						}
					}
				}
			}
		}
	})
	if scanned < 20 {
		t.Fatalf("scanned only %d source files — the scan is not looking at the module", scanned)
	}
}

// TestInvariant_L7_CommonsSchema binds registry ID L7: "hashes, types,
// timestamps, references only."
//
// Every type that enters the shared, witnessed record is checked field by
// field, recursively: only fixed-size byte arrays (hashes, nonces), byte
// slices (keys and signatures — length-pinned at runtime, below), unsigned
// integers (sizes, sequence numbers, closed enums), time.Time, and slices or
// structs built only from those. No string, map, interface, float, pointer,
// func, or channel — so no name, memo, or free text can be expressed. Then
// the runtime rung: a byte-slice field padded past its fixed ed25519 length
// to smuggle data must fail verification and never enter a log.
func TestInvariant_L7_CommonsSchema(t *testing.T) {
	t.Run("commons types carry no open text", testL7Schema)
	t.Run("oversized byte fields never verify", testL7LengthPinned)
}

// commonsTypes is every type that enters a log, a checkpoint, a witness
// countersignature, a proof, or a filing receipt.
var commonsTypes = []interface{}{
	Entry{}, Checkpoint{}, Countersignature{}, Proof{}, WitnessedCheckpoint{},
	FilingCommitment{}, FilingReceipt{}, Transition{},
}

func testL7Schema(t *testing.T) {
	timeType := reflect.TypeOf(time.Time{})
	var check func(path string, typ reflect.Type)
	check = func(path string, typ reflect.Type) {
		if typ == timeType {
			return
		}
		switch typ.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return
		case reflect.Array:
			if typ.Elem().Kind() != reflect.Uint8 {
				t.Errorf("%s: array of %s — only fixed-size byte arrays (hashes) belong in the commons", path, typ.Elem())
			}
		case reflect.Slice:
			if typ.Elem().Kind() == reflect.Uint8 {
				return // keys and signatures; length-pinned at runtime
			}
			check(path+"[]", typ.Elem())
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				check(path+"."+f.Name, f.Type)
			}
		default:
			t.Errorf("%s: field of kind %s (%s) — the commons holds hashes, types, timestamps, and references only", path, typ.Kind(), typ)
		}
	}
	for _, v := range commonsTypes {
		typ := reflect.TypeOf(v)
		if typ.NumField() == 0 {
			t.Fatalf("%s has no fields; the schema check is not looking at it", typ.Name())
		}
		check(typ.Name(), typ)
	}
}

func testL7LengthPinned(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)
	memo := []byte("Alice Example, 12 Main St")

	l, _, _ := buildLog(t, op, a, b, 1)
	base := sealedEntry(t, id, a, b, contentN(0x70), Hash{}, testInstant)

	padded := map[string]Entry{}
	e := base
	e.ProposerSeal = append(append([]byte(nil), base.ProposerSeal...), memo...)
	padded["ProposerSeal"] = e
	e = base
	e.AcceptorSeal = append(append([]byte(nil), base.AcceptorSeal...), memo...)
	padded["AcceptorSeal"] = e
	e = base
	e.Proposer = append(append(ed25519.PublicKey(nil), base.Proposer...), memo...)
	padded["Proposer"] = e

	for field, e := range padded {
		if e.Verify() {
			t.Errorf("Entry with %d extra bytes in %s verified: an open byte field is a PII channel", len(memo), field)
		}
		if _, err := l.Append(e); err == nil {
			t.Errorf("Entry with %d extra bytes in %s entered the log", len(memo), field)
		}
	}

	cp := l.Checkpoint(testInstant)
	cp.Sign(op.priv)
	cp.Signature = append(cp.Signature, memo...)
	if cp.Verify(op.pub) {
		t.Error("Checkpoint with a padded signature verified")
	}
}

// --- shared source-scan helpers -------------------------------------------

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
			t.Fatal("no go.mod above the record package")
		}
		dir = parent
	}
}

func walkSource(t *testing.T, root string, fn func(rel string, f *ast.File)) {
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
		f, err := parser.ParseFile(fset, path, nil, 0)
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

func receiverName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return receiverName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return receiverName(x.X)
	}
	return ""
}
