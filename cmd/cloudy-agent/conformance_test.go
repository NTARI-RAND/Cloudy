package main

// JFA conformance binding for the node agent. Test names carry the Janus
// registry ID they bind: TestInvariant_<ID>_<Name>, with "-" written "_".

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestInvariant_SUB_no_inbound_requirement_AgentNeverListens binds registry
// ID SUB-no-inbound-requirement on the node side: a member's machine
// contributes "without requiring open inbound ports or a static address".
// sohocloud-protocol binds the wire (the pull model); this binds the agent
// that runs on the member's machine:
//
//   - no file in the agent, or in any Cloudy package it imports, opens or
//     serves on a listening socket (Listen*, ListenAndServe*, FileListener,
//     FilePacketConn, or a networking package's Serve/ServeTLS), or hides net
//     calls behind a dot-import;
//   - the agent → coordinator loop completes its lifecycle — list,
//     heartbeat, poll, run, report, decline — making every call itself
//     (TestLoopLifecycle drives it over the reference HTTP+JSON wire).
//
// Residual, named: a real NAT/CGNAT path is a multi-node test (Phase 2), and
// third-party packages (the standard library, sohocloud-protocol) are not
// scanned here; the protocol binds its own.
func TestInvariant_SUB_no_inbound_requirement_AgentNeverListens(t *testing.T) {
	t.Run("nothing the agent runs listens", testAgentNoListener)
	t.Run("the loop completes over outbound calls", TestLoopLifecycle)
}

// listenCalls open or serve on a listening socket, whatever they are called
// on. A server's Serve method needs a listener, so it is caught through the
// Listen or FileListener call that made one.
var listenCalls = map[string]bool{
	"Listen": true, "ListenTCP": true, "ListenUDP": true, "ListenIP": true,
	"ListenUnix": true, "ListenUnixgram": true, "ListenPacket": true,
	"ListenMulticastUDP": true, "ListenAndServe": true, "ListenAndServeTLS": true,
	"FileListener": true, "FilePacketConn": true,
}

// packageServeCalls serve on a listener when called on a networking package
// itself (http.Serve, fcgi.Serve). On anything else, Serve is just a name —
// the agent's own ServiceExecutor.Serve runs a member's workload.
var packageServeCalls = map[string]bool{"Serve": true, "ServeTLS": true}

func isNetPackage(p string) bool {
	return p == "net" || strings.HasPrefix(p, "net/") || p == "crypto/tls"
}

const modulePath = "github.com/NTARI-RAND/Cloudy"

// agentDirs returns this package's directory and every in-module package it
// imports, transitively, as directories relative to the module root.
func agentDirs(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	seen := map[string]bool{}
	queue := []string{filepath.Join("cmd", "cloudy-agent")}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		for _, f := range parseDir(t, filepath.Join(root, dir)) {
			for _, imp := range f.file.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(p, modulePath+"/") {
					queue = append(queue, filepath.FromSlash(strings.TrimPrefix(p, modulePath+"/")))
				}
			}
		}
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	return out
}

type parsedFile struct {
	name string
	file *ast.File
}

// parseDir parses every non-test Go file in dir.
func parseDir(t *testing.T, dir string) []parsedFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []parsedFile
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Join(dir, n), err)
		}
		out = append(out, parsedFile{name: n, file: f})
	}
	return out
}

func testAgentNoListener(t *testing.T) {
	dirs := agentDirs(t)
	need := map[string]bool{"cmd/cloudy-agent": false, "internal/contribute": false, "internal/coord": false}
	files := 0
	for _, dir := range dirs {
		slash := filepath.ToSlash(dir)
		if _, ok := need[slash]; ok {
			need[slash] = true
		}
		for _, pf := range parseDir(t, filepath.Join("..", "..", dir)) {
			path := slash + "/" + pf.name
			files++
			netNames := map[string]bool{} // local names of imported networking packages
			for _, imp := range pf.file.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if !isNetPackage(p) {
					continue
				}
				switch {
				case imp.Name != nil && imp.Name.Name == ".":
					t.Errorf("%s dot-imports %s: networking calls must stay visible to this audit", path, p)
				case imp.Name != nil:
					netNames[imp.Name.Name] = true
				default:
					netNames[p[strings.LastIndex(p, "/")+1:]] = true
				}
			}
			ast.Inspect(pf.file, func(node ast.Node) bool {
				sel, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, _ := sel.X.(*ast.Ident)
				if listenCalls[sel.Sel.Name] || (packageServeCalls[sel.Sel.Name] && pkg != nil && netNames[pkg.Name]) {
					t.Errorf("%s calls %s: the node agent must never accept inbound connections", path, sel.Sel.Name)
				}
				return true
			})
		}
	}
	for d, found := range need {
		if !found {
			t.Errorf("the scan did not reach %s — it is not following the agent's imports", d)
		}
	}
	if files < 8 {
		t.Fatalf("scanned only %d files — the audit is not looking at the agent", files)
	}
}
