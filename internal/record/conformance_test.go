package record

// JFA conformance bindings for the record layer.
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

// appendOnlyDoc matches a type's doc comment that declares it append-only.
// A type is in scope when its NAME is persistent-shaped OR its DOC says it
// is append-only, so a log named Catalog or Tree cannot slip past by name.
var appendOnlyDoc = regexp.MustCompile(`(?i)append[- ]only`)

// mustTrack are append-only types whose names do not match persistentType;
// if a doc rewording ever drops one out of scope, the scan fails loudly
// instead of silently shrinking.
var mustTrack = []string{
	filepath.Join("internal", "market") + ".Catalog",
	filepath.Join("internal", "techtree") + ".Tree",
}

// testL6NoMutatingVerbs scans every shipped Go file in the module. A method
// on, or an interface declared as, an append-only type must not start with
// an update or delete verb. A type is append-only when its name ends in
// Store/Log/Ledger/Book or its doc comment says "append-only". Locker.Erase
// is the one sanctioned erasure and is out of scope by construction: Locker
// is the member-local store, type-disjoint from every log, and never enters
// a chain.
func testL6NoMutatingVerbs(t *testing.T) {
	root := moduleRoot(t)
	type file struct {
		rel string
		f   *ast.File
	}
	var files []file
	walkSource(t, root, func(rel string, f *ast.File) { files = append(files, file{rel, f}) })
	if len(files) < 20 {
		t.Fatalf("scanned only %d source files — the scan is not looking at the module", len(files))
	}

	// Pass 1: which types are append-only, keyed by package dir + name.
	tracked := map[string]bool{}
	for _, fl := range files {
		dir := filepath.Dir(fl.rel)
		for _, decl := range fl.f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				doc := ts.Doc
				if doc == nil {
					doc = gd.Doc
				}
				if persistentType.MatchString(ts.Name.Name) || (doc != nil && appendOnlyDoc.MatchString(doc.Text())) {
					tracked[dir+"."+ts.Name.Name] = true
				}
			}
		}
	}
	for _, want := range mustTrack {
		if !tracked[want] {
			t.Errorf("%s is append-only but the scan does not track it", want)
		}
	}

	// Pass 2: no mutating verb on any tracked type.
	for _, fl := range files {
		dir := filepath.Dir(fl.rel)
		for _, decl := range fl.f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 || !d.Name.IsExported() {
					continue
				}
				recv := receiverName(d.Recv.List[0].Type)
				if tracked[dir+"."+recv] && mutatingVerb.MatchString(d.Name.Name) {
					t.Errorf("%s: %s.%s is an update or delete verb on an append-only type", fl.rel, recv, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || !tracked[dir+"."+ts.Name.Name] {
						continue
					}
					it, ok := ts.Type.(*ast.InterfaceType)
					if !ok {
						continue
					}
					for _, m := range it.Methods.List {
						for _, n := range m.Names {
							if mutatingVerb.MatchString(n.Name) {
								t.Errorf("%s: interface %s declares %s, an update or delete verb", fl.rel, ts.Name.Name, n.Name)
							}
						}
					}
				}
			}
		}
	}
}

// TestInvariant_L7_CommonsSchema binds registry ID L7: "hashes, types,
// timestamps, references only."
//
// Every type that enters the shared, witnessed record is checked field by
// field, recursively: only fixed-size byte arrays (hashes, nonces), unsigned
// integers (sizes, sequence numbers, closed enums), time.Time, and slices or
// structs built only from those. A byte SLICE is an open channel, so it is
// admitted only where it is named in openBytesAllowed — an ed25519 key or
// signature whose length every Verify pins. No string, map, interface,
// float, pointer, func, or channel, and no unlisted []byte — so no name,
// memo, or free text can be expressed. Then the runtime rung: every
// allowlisted field, padded past its fixed length to smuggle data, must fail
// verification and never enter a log.
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

// openBytesAllowed is the complete list of []byte fields the commons may
// carry, as OwningType.Field. Each is an ed25519 public key or signature, and
// each is padded and refused in testL7LengthPinned. Adding a []byte field to
// a commons type fails testL7Schema until it is listed here AND given a
// padding case below — which is the review moment.
var openBytesAllowed = map[string]bool{
	"Entry.Proposer":             true,
	"Entry.Acceptor":             true,
	"Entry.ProposerSeal":         true,
	"Entry.AcceptorSeal":         true,
	"Checkpoint.Signature":       true,
	"Countersignature.Witness":   true,
	"Countersignature.Signature": true,
	"FilingCommitment.Filer":     true,
	"FilingCommitment.Signature": true,
	"FilingReceipt.Witness":      true,
	"FilingReceipt.Signature":    true,
}

func testL7Schema(t *testing.T) {
	timeType := reflect.TypeOf(time.Time{})
	seen := map[string]bool{}
	// owner is the name of the struct type that declares the field at path.
	var check func(path, owner, field string, typ reflect.Type)
	check = func(path, owner, field string, typ reflect.Type) {
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
				key := owner + "." + field
				if !openBytesAllowed[key] {
					t.Errorf("%s: unlisted []byte field %s — an open byte field is a PII channel; list it in openBytesAllowed only if it is a length-pinned key or signature, and add its padding case", path, key)
				}
				seen[key] = true
				return
			}
			check(path+"[]", owner, field, typ.Elem())
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				check(path+"."+f.Name, typ.Name(), f.Name, f.Type)
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
		check(typ.Name(), "", "", typ)
	}
	// The allowlist must not go stale: every entry names a field that exists.
	for key := range openBytesAllowed {
		if !seen[key] {
			t.Errorf("openBytesAllowed lists %s, which no commons type carries — remove it", key)
		}
	}
}

func testL7LengthPinned(t *testing.T) {
	op := newParty(t)
	a, b := newParty(t), newParty(t)
	id := LogID(op.pub)
	memo := []byte("Alice Example, 12 Main St")
	pad := func(p []byte) []byte { return append(append([]byte(nil), p...), memo...) }
	refused := map[string]bool{}
	expect := func(name string, verified bool) {
		t.Helper()
		if verified {
			t.Errorf("%s padded with %d extra bytes verified: an open byte field is a PII channel", name, len(memo))
		}
		refused[name] = true
	}

	// Entry — positive control first, so a refusal below is caused by the
	// padding and nothing else.
	l, _, _ := buildLog(t, op, a, b, 1)
	base := sealedEntry(t, id, a, b, contentN(0x70), Hash{}, testInstant)
	if !base.Verify() {
		t.Fatal("control: the unpadded entry does not verify")
	}
	for name, mutate := range map[string]func(*Entry){
		"Entry.Proposer":     func(e *Entry) { e.Proposer = pad(e.Proposer) },
		"Entry.Acceptor":     func(e *Entry) { e.Acceptor = pad(e.Acceptor) },
		"Entry.ProposerSeal": func(e *Entry) { e.ProposerSeal = pad(e.ProposerSeal) },
		"Entry.AcceptorSeal": func(e *Entry) { e.AcceptorSeal = pad(e.AcceptorSeal) },
	} {
		e := base
		mutate(&e)
		expect(name, e.Verify())
		if _, err := l.Append(e); err == nil {
			t.Errorf("Entry with padded %s entered the log", name)
		}
	}
	if _, err := l.Append(base); err != nil {
		t.Fatalf("control: the unpadded entry was refused by the log: %v", err)
	}

	// Checkpoint and Countersignature.
	cp := l.Checkpoint(testInstant)
	cp.Sign(op.priv)
	if !cp.Verify(op.pub) {
		t.Fatal("control: the unpadded checkpoint does not verify")
	}
	pcp := cp
	pcp.Signature = pad(cp.Signature)
	expect("Checkpoint.Signature", pcp.Verify(op.pub))

	wit := newParty(t)
	cs, err := NewWitness(wit.priv).Countersign(cp, op.pub, nil)
	if err != nil {
		t.Fatalf("Countersign: %v", err)
	}
	if !cs.Verify(cp) {
		t.Fatal("control: the unpadded countersignature does not verify")
	}
	pcs := cs
	pcs.Witness = pad(cs.Witness)
	expect("Countersignature.Witness", pcs.Verify(cp))
	pcs = cs
	pcs.Signature = pad(cs.Signature)
	expect("Countersignature.Signature", pcs.Verify(cp))

	// FilingCommitment and FilingReceipt.
	filer := newParty(t)
	fc := FilingCommitment{Claim: Hash{0x01}, Exchange: Hash{0x02}, TypeHash: Hash{0x03}, At: testInstant, Filer: filer.pub}
	fc.Sign(filer.priv)
	if !fc.Verify() {
		t.Fatal("control: the unpadded filing commitment does not verify")
	}
	pfc := fc
	pfc.Filer = pad(fc.Filer)
	expect("FilingCommitment.Filer", pfc.Verify())
	pfc = fc
	pfc.Signature = pad(fc.Signature)
	expect("FilingCommitment.Signature", pfc.Verify())

	rc, err := NewFilingIntake(wit.priv).Accept(fc, testInstant)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !rc.Verify() {
		t.Fatal("control: the unpadded filing receipt does not verify")
	}
	prc := rc
	prc.Witness = pad(rc.Witness)
	expect("FilingReceipt.Witness", prc.Verify())
	prc = rc
	prc.Signature = pad(rc.Signature)
	expect("FilingReceipt.Signature", prc.Verify())

	// Every allowlisted open byte field has a padding case.
	for key := range openBytesAllowed {
		if !refused[key] {
			t.Errorf("openBytesAllowed lists %s but no padding case covers it", key)
		}
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
