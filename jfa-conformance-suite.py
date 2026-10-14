#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JFA conformance suite — bound to the official document
(janus-facing-architecture.md, 2026-08-24 rebuild).

The prior instrument and its suite are preserved in Historical Docs as
*-pre-rebuild-2026-08-24.*. Their clause-numbered IDs are retired; this
suite's registry cites the new document's sections by name and its lines
by number (L1-L12). Where an invariant descends from the prior registry,
the old ID is noted for lineage. Which concepts carried, changed, or
retired is recorded in jfa-concept-triage-2026-08-24.md.

What it checks, executably, right now (the DOCUMENT checks):
  * All nine sections are present, in order: Introduction, Principles,
    the five layers (Substrate, Record, Covenant, Governance, Economy &
    Information), The Lines That Cannot Be Crossed, References.
  * Every layer section carries the three tiers in order:
    Protocol, Orchestrator, Frontend.
  * The lines section carries exactly twelve numbered lines.
  * Every registered invariant's anchor phrase appears inside the section
    that carries it, so the text and this registry cannot drift apart.
  * Licensing is stated: AGPL for software, CC BY-SA for the specification.
  * Retired concepts stay retired: the document must not reintroduce
    replay/mirror ledger state, countersigned checkpoints, or the old
    no-central-chain rule (all retired or reversed by the 2026-08-24
    triage), and must carry no product names.
  * The document is PII-free beyond the organizational footer.
  * History is preserved: the document points at Historical Docs, and when
    the folder sits beside the document, the pre-rebuild instrument is
    actually in it.
  * The stack's own open-questions document exists beside the official
    document and its entries carry status.

What it does NOT check, and says so (the DELEGATED registry):
  Invariants that bind running software (zero-sum issuance, the public
  chain, exit survival, ...) or a governance instrument (recallable
  delegates, the escrow-to-credit switch, ...) can only be enforced by
  tests living beside that code or that instrument. They are carried here
  as a registry with stable IDs and reported as delegated and unbound
  until a repo ships tests citing those IDs. Reporting them as "checked"
  from here would be self-attestation wearing a test runner — the
  stand-in is labeled instead.

Usage:
  python jfa-conformance-suite.py                 # check the document
  python jfa-conformance-suite.py --doc PATH      # check another copy
  python jfa-conformance-suite.py --list          # print the registry
  python jfa-conformance-suite.py --project PATH  # check a project repo's
                                                  # open-questions deliverable
  python jfa-conformance-suite.py --bindings REPO [REPO ...]
                                                  # also report which delegated
                                                  # invariants those repos bind

What --bindings does, and what it does not:
  Given one or more implementation repositories (local paths), it scans
  their test files for test functions named TestInvariant_<ID>_<Name>,
  with any "-" in the ID written "_", and marks each registered
  implementation invariant those names cite as BOUND. That is the binding
  P1-001 §9.14(b) defines: "complete when a repository ships tests citing
  the identifier." It does NOT run those tests: whether a bound test
  passes is reported by that repository's own CI, never here, so the
  label says "test present" and nothing more (§9.15). A citation of an
  unregistered ID fails the run, since a misspelled ID would otherwise
  bind nothing silently. A test citing an instrument- or document-bound
  ID is listed but binds nothing: instruments bind through their venue
  tooling (§9.14(c)). Recognized test files: Go *_test.go
  ("func TestInvariant_..."), and JavaScript/TypeScript *.test.* and
  *.spec.* ("test(" / "it(" / "describe(" with a "TestInvariant_..."
  title). Standard library only; offline; no toolchain for the scanned
  language is needed.

Exit code 0 when every executed check passes; 1 otherwise.

Software: AGPL-3.0 · Specification it verifies: CC BY-SA 4.0.
"""

import argparse
import glob
import io
import os
import re
import sys
from collections import namedtuple

# --------------------------------------------------------------------------
# The invariant registry.
#
# id       stable identifier a repo's test suite cites (e.g. "L3",
#          "REC-topology")
# section  the section whose text must contain the anchor (section key,
#          see SECTION_KEYS)
# anchor   normalized phrase that MUST appear inside that section (see
#          normalize)
# binding  where executable enforcement must live:
#            "document"       -- enforced fully by this suite (presence)
#            "implementation" -- enforced by tests beside the code
#            "instrument"     -- enforced by a governance instrument and
#                                its venue tooling
# note     where the delegated enforcement is expected to land; lineage to
#          the pre-rebuild registry where one exists
# --------------------------------------------------------------------------

Invariant = namedtuple("Invariant", "id section anchor binding note")

REGISTRY = [
    # Introduction — posture
    Invariant("INTRO-janus", "intro", "faces demands for both production and consumption",
              "document", "posture statement; carried by presence (reworded 2026-08-27)"),
    Invariant("INTRO-endogenous", "intro", "endogenous mutual credit",
              "document", "posture statement; carried by presence"),
    # Principles
    Invariant("P-coordinate-check", "principles", "never split into rulers and ruled",
              "document", "posture statement; carried by presence (was 2.4)"),
    Invariant("P-cost-of-leaving", "principles", "disciplined by the cost of leaving it",
              "instrument", "governance instrument assigns each layer's discipline by exit cost (was 2.3)"),
    Invariant("P-lean-code", "principles", "auditable whole",
              "implementation", "protocol repo: dependency audit in CI - standard library only; copyleft check (was 8.2)"),
    # Substrate layer — the residential posture
    Invariant("SUB-no-inbound-requirement", "substrate", "without requiring open inbound ports or a static address",
              "implementation", "node tests: a node registers, heartbeats, polls for work and reports over outbound connections only - no listening port, no static IP, behind NAT/CGNAT and dynamic addressing; the residential case of L11 (new 2026-09-08)"),
    Invariant("SUB-redundant-execution", "substrate", "runs on at least two independent hosts",
              "implementation", "substrate tests: work whose result settles a spend or enters the record executes on at least two independent hosts and their disagreement is rated, never trusted; integrity-assured, not confidentiality-assured (open question 9(c) resolved; new 2026-10-07)"),
    # Record layer — the topology
    Invariant("REC-six-holders", "record", "held by six parties",
              "implementation", "record tests: each of the two prosumers, the operator, the orchestrator, and both witnesses keep records beside the chain (was REC-four-holders; recounted 2026-08-27; orchestrator added and anchor retracked 2026-09-30)"),
    Invariant("REC-public-chain", "record", "one public chain distributed across the substrate",
              "implementation", "record tests: single public chain on substrate serving non-parties (reverses old 9.3)"),
    Invariant("REC-truth-not-currency", "record", "never a currency unit",
              "implementation", "federation tests: what crosses record communities is reputation and history only"),
    Invariant("REC-witness-minimum", "record", "label itself unfederated",
              "implementation", "deployment tests: an operator platform with fewer than two independent witnesses forces the unfederated label (was 8.3; reworded 2026-08-25)"),
    Invariant("REC-witness-work", "record", "compensating the prosumers who keep the record",
              "implementation", "substrate tests: record-keeping and witnessing assigned as compensated substrate work (reworded 2026-08-27; anchor retracked to the frontend market wording 2026-09-17)"),
    Invariant("REC-witness-draw", "record", "assigned by a draw seeded from the public chain",
              "implementation", "record tests: witness assignment by a draw seeded from a public-chain block hash, verifiable by anyone; the substrate market pays the witness, never the operator observed (lineage REC-witness-work; new 2026-10-07)"),
    # Covenant layer
    Invariant("COV-adjudicators", "covenant", "the parties to it rate the adjudicator",
              "implementation", "covenant tests: adjudication conduct ratable by the parties to the adjudication - the operator on a platform, the witnesses across platforms (was 7.2-adjudicator-rated; anchor retracked 2026-09-30)"),
    Invariant("COV-operators-adjudicate", "covenant", "platform operators adjudicate between their prosumers",
              "implementation", "dispute tests: adjudication of apparent covenant breaches performed by platform operators (new 2026-08-25)"),
    Invariant("COV-witness-adjudication", "covenant", "adjudicated at the witness layer",
              "implementation", "dispute tests: cross-platform disputes adjudicated by the exchange's witnesses (new 2026-08-25)"),
    Invariant("COV-operator-dispute-witnesses", "covenant", "no operator adjudicates a dispute to which it is a party",
              "instrument", "P1-001 §10.9 routes a prosumer's dispute with its own operator to that platform's standing witnesses; dispute tests: a platform's routing never seats an operator on its own case (new 2026-09-22; lineage COV-operators-adjudicate, COV-witness-adjudication)"),
    # Governance and E&I operational detail (delegates/recall, reopening decided
    # matters, operator economic management, the hybrid definition) moved to the
    # bylaws and companion-article level on 2026-08-27; GOV-delegates, GOV-reopen,
    # EI-operator-economy and EI-hybrid are retired from this registry.
    # Governance layer — membership and the franchise, returned to the document
    # on 2026-09-22 because a vote resting on an instrument the architecture can
    # be read to forbid is a paper check (amendment of 2026-09-22, §1).
    Invariant("GOV-prosumer-membership", "governance", "by participating as a prosumer on a federated platform",
              "instrument", "P1-001 §§3.3, 3.8: a prosumer of a federated platform may take up membership of the stewardship organization on the terms its bylaws provide (new 2026-09-22)"),
    # The lines that cannot be crossed
    Invariant("L1", "lines", "always summing to zero",
              "implementation", "economy tests: each exchange moves two balances netting to zero (was 7.1-zero-sum)"),
    Invariant("L2", "lines", "earned never bought and never redeemable for fiat",
              "implementation", "economy tests: no purchase path, no redemption path (was 9.6)"),
    Invariant("L3", "lines", "no shared unit no conversion between communities",
              "implementation", "economy tests: sovereign units; no convertibility (was 9.7)"),
    Invariant("L4", "lines", "value stays home only truth crosses",
              "implementation", "cross-community tests: only recorded history crosses (was 9.8)"),
    Invariant("L5", "lines", "bound atomically by the public chain",
              "implementation", "cross-community tests: paired sovereign spends bound by the chain; no clearer (was 7.2-atomic-cross, mechanism changed)"),
    Invariant("L6", "lines", "forgive harm by annotating never by erasing",
              "implementation", "record tests: no update-in-place, no delete; dismissal is annotation (was 9.1)"),
    Invariant("L7", "lines", "no narratives no identities in the shared record",
              "implementation", "commons schema tests: hashes, types, timestamps, references only (was 9.2; restored 2026-08-24)"),
    Invariant("L8", "lines", "count of exchanges at each rating level",
              "implementation", "covenant tests: full distribution carried; no scalar score anywhere (was 9.4)"),
    Invariant("L9", "lines", "set by the operator and never derived from reputation",
              "implementation", "boundary tests: one uniform limit per operator community, set by that operator; never per-member, never derived from reputation (was 9.5; operator-set 2026-08-25)"),
    Invariant("L10", "lines", "published to the governance layer",
              "instrument", "escrow switch to hybrid or full mutual credit gated by operator capacity, prosumer-network notice, and published local authorizations to provide mutual credit services, or a published finding that none is required; a switch to full mutual credit further ratified by the deployment's prosumers (was 8.7; regated 2026-08-25; review->authorization 2026-08-31; null case 2026-08-31; ratification 2026-10-07)"),
    Invariant("L11", "lines", "whose removal could stop the network",
              "implementation", "deployment tests: participant-owned hardware; no hosting chokepoint (was 8.1)"),
    Invariant("L12", "lines", "survive any frontend",
              "implementation", "exit tests: positions and history survive frontend and operator loss via the public chain and per-party records (was 7.3-exit/9.9, mechanism changed)"),
]

# Section keys in required order, with the heading each must match.
SECTION_KEYS = [
    ("intro", "Introduction"),
    ("principles", "Principles"),
    ("substrate", "Substrate Layer"),
    ("record", "Record Layer"),
    ("covenant", "Covenant Layer"),
    ("governance", "Governance Layer"),
    ("ei", "Economy & Information Layer"),
    ("lines", "The Lines That Cannot Be Crossed"),
    ("references", "References"),
]

LAYER_KEYS = ["substrate", "record", "covenant", "governance", "ei"]
TIER_TITLES = ["Protocol Tier", "Orchestrator Tier", "Frontend Tier"]
LINE_COUNT = 12

# Product names must not appear anywhere: the document is product-agnostic.
# LBTAS is the covenant, not a product, and may be named wherever the Covenant
# layer label would otherwise be undefined (principal's decision, 2026-09-30).
PRODUCT_NAMES = ["Sohocloud", "SoHoLINK", "Cloudy", "Slack", "Discord", "Mycelium",
                 "Agrinet", "NTARI/OS", "GitHub", "Wix", "Fruitful"]

# Concepts the 2026-08-24 triage retired or reversed; their anchor phrases
# must NOT reappear in the document.
RETIRED_ANCHORS = [
    ("replay of the sealed record", "replay/mirror was retired"),
    ("replayable from sealed records", "replay/mirror was retired"),
    ("countersign", "countersigned checkpoints superseded by the public chain"),
    ("there is no central chain", "reversed: the public chain is the architecture"),
    ("no central chain", "reversed: the public chain is the architecture"),
]


def normalize(text):
    """Lowercase; strip markdown emphasis; fold dashes and punctuation to
    spaces; collapse whitespace. Anchors are written in this normal form."""
    text = text.lower()
    text = re.sub(r"[*_`>#|]", "", text)
    text = re.sub(u"[–—-]", " ", text)
    text = re.sub(u"[(),;:.\"'“”‘’?!→·&\\[\\]]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


class Result:
    def __init__(self, name, ok, detail=""):
        self.name, self.ok, self.detail = name, ok, detail


def parse_document(doc):
    """Split the document into '## ' sections, each holding its full text
    and an ordered list of its '### ' subsection titles."""
    sections = []
    cur = None
    for line in doc.splitlines():
        m = re.match(r"^## (.+?)\s*$", line)
        if m:
            cur = {"title": m.group(1), "text": "", "subs": []}
            sections.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^### (.+?)\s*$", line)
        if m:
            cur["subs"].append(m.group(1))
        cur["text"] += line + "\n"
    return sections


def key_sections(sections):
    """Map section keys to parsed sections by matching expected titles."""
    by_key = {}
    for key, title in SECTION_KEYS:
        for sec in sections:
            if normalize(sec["title"]) == normalize(title):
                by_key[key] = sec
                break
    return by_key


# --------------------------------------------------------------------------
# Document checks
# --------------------------------------------------------------------------

def check_sections(sections):
    problems = []
    expected = [normalize(title) for _, title in SECTION_KEYS]
    got = [normalize(s["title"]) for s in sections]
    missing = [t for t in expected if t not in got]
    if missing:
        problems.append("missing sections: %s" % ", ".join(missing))
    else:
        order = [got.index(t) for t in expected]
        if order != sorted(order):
            problems.append("sections out of order: %s" % got)
    return Result("D1 nine sections present, ordered, titled", not problems,
                  "; ".join(problems))


def check_tiers(by_key):
    problems = []
    for key in LAYER_KEYS:
        sec = by_key.get(key)
        if sec is None:
            problems.append("layer '%s' absent" % key)
            continue
        if sec["subs"] != TIER_TITLES:
            problems.append("%s tiers %s, expected %s" % (key, sec["subs"], TIER_TITLES))
    return Result("D2 every layer carries Protocol/Orchestrator/Frontend in order",
                  not problems, "; ".join(problems))


def check_lines(by_key):
    sec = by_key.get("lines")
    if sec is None:
        return Result("D3 the twelve lines intact", False, "lines section absent")
    numbers = [int(m) for m in re.findall(r"^(\d+)\.\s", sec["text"], re.M)]
    ok = numbers == list(range(1, LINE_COUNT + 1))
    return Result("D3 the twelve lines intact", ok,
                  "" if ok else "found numbered lines %s" % numbers)


def check_registry_anchors(by_key):
    problems = []
    for inv in REGISTRY:
        sec = by_key.get(inv.section)
        if sec is None:
            problems.append("%s: section '%s' not found" % (inv.id, inv.section))
        elif inv.anchor not in normalize(sec["text"]):
            problems.append("%s: anchor absent from section '%s'" % (inv.id, inv.section))
    return Result("D4 registered anchors present in their sections", not problems,
                  "; ".join(problems) if problems
                  else "%d registered invariants anchored to their sections" % len(REGISTRY))


def check_licensing(doc):
    norm = normalize(doc)
    problems = []
    if "affero general public license" not in norm and "agpl" not in norm:
        problems.append("AGPL not stated for the software")
    if "cc by sa" not in norm and "sharealike" not in norm:
        problems.append("CC BY-SA not stated for the specification")
    return Result("D5 licensing stated (AGPL software, CC BY-SA spec)",
                  not problems, "; ".join(problems))


def check_retired(doc):
    norm = normalize(doc)
    hits = ["'%s' (%s)" % (anchor, why) for anchor, why in RETIRED_ANCHORS
            if anchor in norm]
    hits += [name for name in PRODUCT_NAMES
             if re.search(r"(?<![A-Za-z])" + re.escape(name) + r"(?![A-Za-z])", doc)]
    return Result("D6 retired concepts stay retired; no product names", not hits,
                  ("found: " + ", ".join(hits)) if hits else "")


def check_no_pii(doc):
    emails = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", doc))
    emails.discard("info@ntari.org")
    return Result("D7 no PII beyond the organizational footer", not emails,
                  ("unexpected addresses: " + ", ".join(sorted(emails))) if emails else "")


def check_history(doc, doc_path):
    problems = []
    if "historical docs" not in normalize(doc):
        problems.append("document does not point at Historical Docs")
    hist = os.path.join(os.path.dirname(os.path.abspath(doc_path)), "Historical Docs")
    detail = ""
    if os.path.isdir(hist):
        if not glob.glob(os.path.join(hist, "janus-facing-architecture-pre-*")):
            problems.append("Historical Docs holds no pre-* instrument")
        else:
            detail = "prior instrument preserved in Historical Docs"
    else:
        detail = "folder not beside this copy; text reference verified only"
    return Result("D8 history preserved and referenced", not problems,
                  "; ".join(problems) if problems else detail)


def check_own_open_questions(doc, doc_path):
    problems = []
    if "open questions" not in normalize(doc):
        problems.append("document does not point at its open-questions file")
    oq = os.path.join(os.path.dirname(os.path.abspath(doc_path)), "OPEN-QUESTIONS.md")
    detail = ""
    if os.path.isfile(oq):
        text = io.open(oq, encoding="utf-8", errors="replace").read()
        if "status" not in normalize(text):
            problems.append("OPEN-QUESTIONS.md entries carry no status")
        else:
            detail = "OPEN-QUESTIONS.md present with status language"
    else:
        problems.append("OPEN-QUESTIONS.md absent beside the document")
    return Result("D9 the stack's own open-questions document is alive", not problems,
                  "; ".join(problems) if problems else detail)


# --------------------------------------------------------------------------
# Per-project check: the living open-questions deliverable
# --------------------------------------------------------------------------

def check_project(path):
    results = []
    candidates = ["OPEN-QUESTIONS.md", "OPEN_QUESTIONS.md", "open-questions.md",
                  os.path.join("docs", "open-questions.md")]
    found = None
    for c in candidates:
        p = os.path.join(path, c)
        if os.path.isfile(p):
            found = p
            break
    if not found:
        results.append(Result("P1 open-questions document exists", False,
                              "none of: " + ", ".join(candidates)))
        return results
    text = io.open(found, encoding="utf-8", errors="replace").read()
    results.append(Result("P1 open-questions document exists", True, found))
    norm = normalize(text)
    entries = len(re.findall(r"^(?:#{2,4} |\- |\d+\. )", text, re.M))
    results.append(Result("P2 document has entries", entries > 0,
                          "%d candidate entries" % entries))
    has_status = "status" in norm
    results.append(Result("P3 entries carry status", has_status,
                          "" if has_status else "no 'status' language found"))
    has_constraints = ("constraint" in norm or "invariant" in norm
                       or "inherits" in norm or "line" in norm)
    results.append(Result("P4 entries name inherited constraints", has_constraints,
                          "" if has_constraints else
                          "no constraints/lines language found"))
    conf = os.path.join(path, "CONFORMANCE.md")
    results.append(Result("P5 conformance self-description present", os.path.isfile(conf),
                          conf if os.path.isfile(conf) else
                          "CONFORMANCE.md absent (warning-level: required once the repo "
                          "claims conformance)"))
    return results


# --------------------------------------------------------------------------
# Bindings: which delegated invariants implementation repos cite in tests
# --------------------------------------------------------------------------

Citation = namedtuple("Citation", "repo path test inv_id")

SKIP_DIRS = {".git", "vendor", "node_modules", "testdata", "dist", "build"}

GO_TEST = re.compile(r"^func\s+(TestInvariant_\w+)\s*\(\s*\w+\s+\*testing\.T\s*\)", re.M)
JS_TEST = re.compile(r"\b(?:test|it|describe)\s*\(\s*[\'\"`](TestInvariant_\w+)")


def _is_test_file(name):
    if name.endswith("_test.go"):
        return GO_TEST
    if re.search(r"\.(test|spec)\.(js|jsx|ts|tsx|mjs|cjs)$", name):
        return JS_TEST
    return None


def resolve_test_id(test_name):
    """Map TestInvariant_<ID>_<Name> to a registered ID by the longest
    registered ID (with "-" written "_") that the name starts with and that
    is followed by "_" or the end. Returns None when nothing matches."""
    rest = test_name[len("TestInvariant_"):]
    best = None
    for inv in REGISTRY:
        key = inv.id.replace("-", "_")
        if rest == key or rest.startswith(key + "_"):
            if best is None or len(key) > len(best.id.replace("-", "_")):
                best = inv
    return best.id if best else None


def scan_bindings(repo):
    """Return (citations, unknown) for one repository path: every
    TestInvariant_ test function found in its test files, resolved to a
    registry ID, and the test names that cite no registered ID."""
    citations, unknown = [], []
    label = os.path.basename(os.path.abspath(repo))
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            pattern = _is_test_file(name)
            if pattern is None:
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, repo).replace(os.sep, "/")
            text = io.open(path, encoding="utf-8", errors="replace").read()
            for test in pattern.findall(text):
                inv_id = resolve_test_id(test)
                if inv_id is None:
                    unknown.append(Citation(label, rel, test, None))
                else:
                    citations.append(Citation(label, rel, test, inv_id))
    return citations, unknown


def check_bindings(repos):
    """Scan every repo; return (results, citations_by_id, informational)."""
    results, by_id, info = [], {}, []
    binding_of = dict((inv.id, inv.binding) for inv in REGISTRY)
    for repo in repos:
        if not os.path.isdir(repo):
            results.append(Result("B1 bindings repo readable: %s" % repo, False,
                                  "not a directory"))
            continue
        citations, unknown = scan_bindings(repo)
        results.append(Result("B1 bindings repo readable: %s" % repo, True,
                              "%d TestInvariant_ tests found" % (len(citations) + len(unknown))))
        if unknown:
            results.append(Result(
                "B2 every TestInvariant_ test cites a registered ID: %s" % repo, False,
                "; ".join("%s (%s)" % (c.test, c.path) for c in unknown)))
        else:
            results.append(Result(
                "B2 every TestInvariant_ test cites a registered ID: %s" % repo, True))
        for c in citations:
            if binding_of[c.inv_id] == "implementation":
                by_id.setdefault(c.inv_id, []).append(c)
            else:
                info.append(c)
    return results, by_id, info


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_results(title, results):
    print(title)
    print("-" * len(title))
    for r in results:
        mark = "[PASS]" if r.ok else "[FAIL]"
        line = "%s %s" % (mark, r.name)
        if r.detail:
            line += " -- " + r.detail
        print(line)
    print()


def print_delegation(bound=None, info=None):
    """List delegated invariants. With bound (from --bindings), mark those a
    scanned repo cites in a test as BOUND — test present, not executed here."""
    delegated = [inv for inv in REGISTRY if inv.binding != "document"]
    if bound is None:
        print("Delegated invariants (labeled stand-ins; unbound until a repo or")
        print("instrument ships checks citing these IDs)")
        print("-" * 60)
        for inv in delegated:
            print("[DELEGATED:%s] %-22s %s" % (inv.binding, inv.id, inv.note))
        print()
        print("%d of %d registered invariants are delegated; this suite binds the"
              % (len(delegated), len(REGISTRY)))
        print("document layer only. A conformant repo cites the IDs above in its")
        print("own test suite; until then, its conformance is self-attested.")
        print()
        return

    print("Delegated invariants and their bindings (BOUND = a scanned repo ships")
    print("a test citing the ID; this suite does not run it -- pass/fail is that")
    print("repo's own CI. Everything else stays self-attested.)")
    print("-" * 60)
    for inv in delegated:
        cites = bound.get(inv.id, [])
        if cites:
            where = ", ".join("%s/%s %s" % (c.repo, c.path, c.test) for c in cites)
            print("[BOUND:%s] %-22s %s" % (inv.binding, inv.id, where))
        else:
            print("[DELEGATED:%s] %-22s %s" % (inv.binding, inv.id, inv.note))
    print()
    for c in info or []:
        print("[NOTE] %s/%s %s cites %s, which binds through an instrument or the"
              % (c.repo, c.path, c.test, c.inv_id))
        print("       document, not a test; listed, not counted")
    if info:
        print()
    impl = [inv for inv in delegated if inv.binding == "implementation"]
    inst = [inv for inv in delegated if inv.binding == "instrument"]
    n_impl = sum(1 for inv in impl if inv.id in bound)
    print("%d of %d implementation-bound invariants are bound by tests (test"
          % (n_impl, len(impl)))
    print("present; results come from each repo's CI). %d of %d instrument-bound"
          % (0, len(inst)))
    print("invariants are bound here: instruments bind through their venue tooling.")
    print("%d of %d delegated invariants remain self-attested."
          % (len(delegated) - n_impl, len(delegated)))
    print()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="JFA conformance suite")
    ap.add_argument("--doc", default=os.path.join(here, "janus-facing-architecture.md"))
    ap.add_argument("--project", help="path to a project repo to check for the "
                                      "open-questions deliverable")
    ap.add_argument("--list", action="store_true", help="print the invariant registry")
    ap.add_argument("--bindings", nargs="+", metavar="REPO",
                    help="implementation repo path(s) to scan for TestInvariant_<ID> "
                         "tests; reports which delegated invariants they bind")
    args = ap.parse_args()

    if args.list:
        for inv in REGISTRY:
            print("%-22s section %-11s [%s] anchor='%s'"
                  % (inv.id, inv.section, inv.binding, inv.anchor))
            print("        enforcement: %s" % inv.note)
        return 0

    all_ok = True

    if args.project and args.bindings:
        print("--bindings reports against the document; run it without --project")
        return 1

    if args.project:
        results = check_project(args.project)
        print_results("PROJECT CHECKS: %s" % args.project, results)
        # P5 is warning-level; it reports but does not fail the run.
        all_ok = all(r.ok for r in results if not r.name.startswith("P5"))
    else:
        if not os.path.isfile(args.doc):
            print("document not found: %s" % args.doc)
            return 1
        doc = io.open(args.doc, encoding="utf-8").read()
        sections = parse_document(doc)
        by_key = key_sections(sections)
        results = [
            check_sections(sections),
            check_tiers(by_key),
            check_lines(by_key),
            check_registry_anchors(by_key),
            check_licensing(doc),
            check_retired(doc),
            check_no_pii(doc),
            check_history(doc, args.doc),
            check_own_open_questions(doc, args.doc),
        ]
        print_results("DOCUMENT CHECKS: %s" % os.path.basename(args.doc), results)
        all_ok = all(r.ok for r in results)
        if args.bindings:
            b_results, bound, info = check_bindings(args.bindings)
            print_results("BINDINGS CHECKS", b_results)
            print_delegation(bound, info)
            all_ok = all_ok and all(r.ok for r in b_results)
        else:
            print_delegation()

    print("RESULT: %s" % ("all executed checks PASS" if all_ok else "FAILURES present"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
