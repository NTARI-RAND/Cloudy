# Contributing

This repository carries the official JFA document, its translations, and the
conformance suite that binds the prose to the invariant registry. Two rules
govern every change: **sign your commits off**, and **keep the suite green**.

## Amendments go into the document

Propose a change by editing the document and opening a pull request. The diff
is the proposal, and the board approves or rejects it in review. Do not add
proposal files or version-documentation alongside the standard — git history is
the version record, and a parallel proposal document starts drifting from the
text it describes the moment it is merged.

Text that is settled goes into the document. Anything still unsettled goes into
[OPEN-QUESTIONS.md](OPEN-QUESTIONS.md) as a numbered entry carrying a
`**Status:**` line and an `**Inherits:**` line, in the style of the entries
already there. Update the count in that file's opening paragraph when you add
one. This split is not cosmetic: merging a document edit makes the text
normative, so a question that is still open cannot ride in on it.

## Sign-off (DCO)

Every commit needs a `Signed-off-by` trailer. The DCO check requires the name
and email in that trailer to match the commit author exactly, so let git add it
rather than typing it by hand:

```
git commit -s
```

If the check fails on an existing branch, add the trailer to every commit and
force-push:

```
git rebase HEAD~<n> --signoff
git push --force-with-lease
```

## The conformance suite

```
python jfa-conformance-suite.py                 # check the document
python jfa-conformance-suite.py --list          # print the invariant registry
python jfa-conformance-suite.py --bindings ../Cloudy   # report which delegated
                                                       # invariants a repo binds
```

Exit code 0 when every executed check passes, 1 otherwise. It runs on every
pull request as the **Conformance** check and takes well under a second.

To catch failures before you push, install the hook once in your clone:

```
git config core.hooksPath .githooks
```

That is a convenience, not a gate — hooks are not distributed with the
repository, and `git push --no-verify` skips them. The pull request check is
what actually holds.

### What the suite constrains

Edits to the document fail the suite if they:

- drop or reorder the nine `##` sections. Additional `##` sections are fine.
- add a `###` heading inside one of the five layer sections. Each must carry
  exactly Protocol Tier, Orchestrator Tier and Frontend Tier, in that order.
  Put new prose in the body of an existing tier.
- leave *The Lines That Cannot Be Crossed* with any count but twelve.
- remove or reword a registered anchor phrase. Twenty-five invariants are
  anchored to the sections that carry them; run `--list` to see them, and
  prefer appending to rewriting.
- name a product. The document is product-agnostic.
- introduce an email address other than the organizational footer's.

## Translations

The English document is authoritative; translations are for reach, not
interpretation. The suite checks the English document only. If you amend it,
say in the pull request whether the translations should be updated before the
change is adopted or after.
