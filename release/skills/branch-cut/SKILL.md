---
name: release-branch-cut
description: >
  Cut a release branch with the `release branch cut` command: create the branch,
  apply the version-reference edits, tag it, and push. Use this skill when
  cutting a release branch, when a cut failed partway and needs to resume, or when
  a version-bearing file has moved and the cut's edits need updating.
---

# Cutting a release branch

`release branch cut` cuts a new release branch, applies the version-reference
edits, tags it, and pushes. It is resumable: if a step fails, fix the cause and
run the same command again — steps that already finished are detected and
skipped.

Run `release branch cut --help` for the authoritative flag list; the flags are
defined in [`release/cmd/flags.go`](../../cmd/flags.go).
This skill covers intent and the recovery story, not a copy of the flag list —
prefer `--help` when the two disagree.

Three branch roles show up throughout:

- **main** — the default branch (master).
- **source** — the branch the cut is taken from. Same as main (master).
- **derived** — the new branch the cut produces.

## Cut a branch

From master, run `release branch cut`. It creates the derived branch, applies the
version-reference edits on it, commits, and pushes. The derived branch inherits
master's current dev tag; master advances to its next dev version with a new tag.

Options:

- **Preview:** `release branch cut --plan` reports each step as `will run`,
  `done`, or `skip` and changes nothing.
- **Skip a step:** `--skip <step-name>` (repeatable). Valid names are the step
  constants in `driver.go`; an unknown name is rejected.

## The steps and how resume works

The cut runs a fixed, ordered list of check-then-act steps. The authoritative
list is the `step*` constants and `stepNames` in
[`release/internal/branch/driver.go`](../../internal/branch/driver.go) — read
them there rather than trusting a copy here. Each step first _checks_ whether its
effect is already in place (branch exists, files already at their new values,
tags present, refs already pushed and matching) and skips itself if so.

That check-first design is the whole recovery story:

- **Resume after a failure:** fix whatever the failed step reported, then run the
  same command again — it picks up at the first not-done step. Recovery is by
  re-running, not rollback. A fresh cut refuses to start on a dirty working tree;
  a resume does not.

A fresh cut branches off current code: before it starts, it checks master is
current with its remote. The check never moves a branch — it only compares the
local tip to the remote tip. Any difference (behind, ahead, a real divergence, or
no branch on the remote) counts as not current. Master is checked against its
configured upstream (`.git/config`). `--plan` only reports what a real cut would
find; a resume skips the check.

When master is not current the cut stops. Sync it, then re-run:
`git checkout master && git pull`.

The manager owns its edit list, so the cut tolerates repo drift. The edits are
defined by the manager, not the shared cut engine.

- Calico: `derivedBranchEdits` in
  [`release/pkg/manager/calico/manager.go`](../../pkg/manager/calico/manager.go).

The manager passes its edits to the driver, which applies them through the generic applier in
[`release/internal/branch/edits.go`](../../internal/branch/edits.go). Every edit
is non-fatal, unless otherwise specified: a file that has moved or been removed is
logged and skipped, not failed for non-fatal edits.

To fix or add an edit when a version-bearing file changes:

- Edit the manager's edit function above. An edit is
  `Edit{File, Pattern, Replacement, Required}`; `Pattern` is an anchored regexp
  against the file's line and `Replacement` is the new line. A pattern that does
  not match is skipped silently, so match the real line — check the file.
- Repository setup that is not a plain version-reference edit (chart values, code
  generation) lives in the manager's prepare-branch hook, not the edit list.
