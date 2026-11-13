---
name: release-backport
description: >
  Cherry-pick a merged master PR onto an active release branch in this
  repo (e.g. master → release-v3.32), or normalise an existing
  cherry-pick PR that was created by `hack/cherry-pick-pull` or by hand
  so its title, body, metadata, and labels match the project
  convention. Use whenever the user asks to cherry-pick, backport, or
  pick a master PR onto a release branch, or asks to fix up / normalise
  an existing cherry-pick PR. Triggers: "backport #NNNNN to
  release-vX.Y", "cherry-pick this to release-vX.Y", "pick #NNNNN onto
  release-vX.Y", "fix up my cherry-pick PR #NNNNN", "normalise this
  cherry-pick PR". Single or multiple PRs.
---

# Release backport

Cherry-pick merged master PRs onto active release branches in this
repo, or normalise an existing cherry-pick PR. Equivalent to running
`hack/cherry-pick-pull` but with you resolving conflicts inline
instead of being prompted interactively, plus a follow-up mode for
fixing up PRs created by other means.

## Backport candidacy

Release backports happen only for changes that *should* ship in an
existing release, bug fixes and the like, not new features. This is
signalled by the `cherry-pick-candidate` label on the master PR,
applied automatically by a GitHub Action that runs an AI classifier
and adds (or omits) the label based on its decision. A maintainer can
still add or remove it by hand.

Before starting any release backport, double-check candidacy, don't
blindly backport whatever you're handed:

1. **Label check.** Fetch the master PR's labels. If
   `cherry-pick-candidate` is present, proceed.
2. **Heuristic check if the label is absent.** Don't silently proceed.
   Apply the classifier's signals to the PR title/body and surface a
   recommendation, then ask the user to confirm before picking:

   | Lean **backport** (candidate) | Lean **skip** (not a candidate) |
   |---|---|
   | Bug fix: `fix`, `regression`, `incorrect`, `broken`, `stuck`, `hang`, `deadlock`, `should be` | New feature: title starts `Add`/`Implement`/`Introduce`/`Enable`/`Support` |
   | Crash: `panic`, `nil pointer`, `segfault`, `crash`, `assertion` | Refactor/cleanup: `Refactor`/`Move`/`Rename`/`Drop`/`Remove unused`, "no behavior change" |
   | Race: `race`, `data race`, `race condition` | Test-only (`*_test.go`, `*fv*`, `*e2e*`) or docs/comment-only |
   | Leak: `memory leak`, `goroutine leak`, `fd leak`, `unbounded`, `accumulates` | Release prep / version bump |
   | Security/hardening: `sanitize`, `harden`, `DoS`, `credential`, `token`, `expose` | Dependency update (Renovate/Dependabot/module bump) |

   Tie-breaks: a fix mixed with feature work leans backport (fixes
   win); if both title and body are vague, lean skip and let the
   human decide. A false backport is more annoying than a missed one.

If the conclusion is "not a candidate" and the user hasn't explicitly
overridden, stop and report rather than opening the release PR.

## Modes

This skill handles two shapes. Decide which one applies before
starting.

**Mode A: Pick from scratch.** User asks the skill to backport a
master PR; no cherry-pick branch or release PR exists yet. Skill
creates the branch, runs `git cherry-pick`, resolves conflicts inline,
runs codegen if needed, pushes, opens the release PR with the right
title / body / labels.

**Mode B: Fix up an existing cherry-pick PR.** User already ran
`hack/cherry-pick-pull` or made the pick by hand; an open release PR
exists. Skill reads the existing PR and edits it so the title prefix,
cherry-pick-history block, metadata expander, and label set match the
convention. No code changes; only `gh pr edit`.

How to tell: if the user names a release PR number that's already
open against `release-v*`, default to Mode B. If the user names a
master PR and asks for a backport, default to Mode A. When uncertain,
ask.

## Prerequisites

For Mode A:
- Be in a `projectcalico/calico` clone. Run `git remote -v` and
  identify the canonical remote (often `upstream` or `origin` pointing
  at `projectcalico/calico`) and your fork remote (where you push
  the cherry-pick branch from).
- Verify the working copy is clean (`git status --porcelain`). If
  there are uncommitted changes, tell the user and stop.
- Note the current branch (`git branch --show-current`) so you can
  return to it at the end.

Mode B only edits an existing PR via `gh`; no local clone state is
required, though running from a clone is convenient.

## Mode A workflow (cherry-pick from scratch)

### 1. Gather master PR metadata

```bash
gh pr view <PR> --repo projectcalico/calico \
  --json title,body,labels,mergeCommit,headRefOid,state
```

Verify the PR is **MERGED**. If not, stop, cherry-pick needs a merge
commit.

Extract:
- `title`, strip any existing `[...]` prefix (from prior cherry-picks)
- `body`, the full PR description
- `labels[].name`, all label names
- `mergeCommit.oid`, the merge commit SHA (fall back to `headRefOid`)

### 2. Run the candidacy check

Apply the **Backport candidacy** section above to the metadata you
just gathered. If the conclusion is "not a candidate" and the user
hasn't explicitly overridden, stop and report rather than continuing.

### 3. Fetch the canonical remote and create the branch

```bash
git fetch <canonical-remote>
git checkout -b auto-pick-of-#<PR>-<canonical-remote>-<target-branch>-<timestamp> \
  <canonical-remote>/<target-branch>
```

Use a timestamp suffix (e.g. `$(date +%s)`) on the **local** branch
name to avoid collisions with leftover branches from previous picks.
When pushing, push to your fork without the timestamp:

```bash
git push <fork-remote> <local-branch-with-timestamp>:auto-pick-of-#<PR>-<canonical-remote>-<target-branch>
```

Branch naming (canonical push target, without timestamp):
- Single PR: `auto-pick-of-#11993-origin-release-v3.32`
- Multiple: `auto-pick-of-#11959-#11960-origin-release-v3.32`

The user names the target release branch in every backport
invocation; the skill does not enumerate active releases on its own.

### 4. Cherry-pick

```bash
git cherry-pick -x --mainline=1 <merge-commit-sha>
```

`--mainline=1` is required because these are merge commits. `-x`
annotates the resulting commit with the original SHA.

**Resolving conflicts:**

If `git cherry-pick` exits non-zero, check
`git diff --name-only --diff-filter=U` for conflicted files. Read
the conflict markers, resolve them, then:

```bash
git add <resolved-files>
git cherry-pick --continue --no-edit
```

Common conflicts:
- **Copyright year**: take the newer year.
- **Import ordering**: resolve, then let `make fix-changed` clean up
  later.

For multiple PRs, cherry-pick each merge commit in sequence.

**Cherry-pick not applicable (empty commit):**

If `git cherry-pick --continue` reports the commit is empty, the
changes are already on the target branch. Run `git cherry-pick --skip`,
note which PRs were skipped, and tell the user.

**For multi-PR picks**, track which PRs were skipped vs successfully
picked. Continue cherry-picking the remaining PRs in sequence. At the
end:

- **All PRs skipped**: clean up the branch, do not create a target
  PR, and report which PRs were skipped and why.
- **Some PRs skipped, some picked**: proceed with the normal workflow
  (steps 5-7) for the successfully picked PRs. Exclude the skipped
  PRs from the branch name, PR title, and PR body. Mention the
  skipped PRs in the PR body as a note (e.g., "Skipped
  projectcalico/calico#NNNN, already on release-vX.Y").
- **Single PR skipped**: clean up the branch, do not create a
  target PR.

In all cases, tell the user which PRs were skipped and why.

### 5. Run code generation if needed

After the cherry-pick, check which files changed and run the
appropriate generation targets. Use `git diff HEAD~1 --name-only` to
get the list of changed files, then apply **all** matching rules:

| Changed files match | Run |
|---|---|
| `api/` | `make -C api gen-files` |
| `*.proto` | `make protobuf` |
| `charts/` | `make gen-manifests` |
| `.semaphore/semaphore.yml.d/` | `make gen-semaphore-yaml` |

If **any** of the above matched, also run `make generate` as a
catch-all to pick up anything the individual targets might miss
(e.g., cross-component codegen dependencies). This is cheap compared
to debugging CI failures from stale generated files.

Commit any regenerated files as a separate commit on top of the
cherry-pick.

### 6. Push and create the release PR

```bash
git push <fork-remote> <local-branch-with-timestamp>:<canonical-branch-name>
```

Then create the PR with the format in **PR conventions** below.

Write the body to a temp file first, then pass it to `gh` via
`--body-file`. Do not use `$(cat <<'EOF' ... EOF)` inline; that form
trips shell expansion checks and is brittle in agent shells.

```bash
cat > /tmp/release-pr-body.md <<'EOF'
<body>
EOF

gh pr create \
  --repo projectcalico/calico \
  -H "<fork-owner>:<canonical-branch-name>" \
  -B "<target-branch>" \
  -t "<title>" \
  -l "<labels>" \
  --body-file /tmp/release-pr-body.md
```

### 7. Clean up

Return to the original branch you noted in prerequisites and report
the PR URL.

## Mode B workflow (fix up an existing cherry-pick PR)

Use this when the user already ran `hack/cherry-pick-pull` or made
the pick by hand, and they want the open release PR normalised.

### 1. Read the existing release PR

```bash
gh pr view <release-pr> --repo projectcalico/calico \
  --json number,title,body,labels,baseRefName,headRefName,state
```

Confirm:
- `state` is `OPEN`.
- `baseRefName` matches `release-v\d+\.\d+`; otherwise stop, this
  isn't a release backport.

### 2. Identify the source master PR

The cherry-pick PR should reference its source. Look in this order:

- Branch name like `auto-pick-of-#<NNNN>-...` or
  `automated-cherry-pick-of-#<NNNN>-...` → extract `<NNNN>`.
- Body's `**Original PR ID**` field in the metadata expander, if
  present.
- Body text mentioning `projectcalico/calico#<NNNN>` or `#<NNNN>` in
  a cherry-pick-history block.
- `-x` annotations in the cherry-pick commit message (look for the
  original SHA, then
  `gh api /repos/projectcalico/calico/commits/<sha>/pulls --jq '.[0].number'`
  to find the PR for that SHA).

If none of those resolve cleanly, ask the user for the source master
PR number rather than guessing.

### 3. Run the candidacy check on the source PR

Same as the **Backport candidacy** section at the top. If it should
not have been backported, surface that to the user rather than
applying cosmetic fixes to a PR that shouldn't exist.

### 4. Recompute the right title, body, and labels

See **PR conventions** below for the exact formats. Compute the
desired title, body, and label set from the source master PR and the
target release branch.

### 5. Show the diff and confirm

Before mutating, produce a concrete diff the user can act on. Do not
summarise; show the actual change.

Write the current body and the proposed body to temp files and
unified-diff them:

```bash
gh pr view <release-pr> --repo projectcalico/calico --json body --jq .body \
  > /tmp/release-pr.current
cat > /tmp/release-pr.proposed <<'EOF'
<proposed body>
EOF
diff -u /tmp/release-pr.current /tmp/release-pr.proposed
```

Also report:
- Title: `<old>` then `<new>`, or "(unchanged)" if identical.
- Labels to add: comma list, or "(none)".
- Labels to remove: comma list, or "(none)".

**Operational rule for "additive":** if the existing body, with
leading and trailing whitespace stripped, does not appear verbatim
somewhere inside the proposed body, treat the existing body as
custom content. In that case, keep the existing body as-is and only
inject the cherry-pick-history block above it and the metadata
expander below it. Never rewrite the author's prose.

Ask the user to confirm before applying. If they decline, stop
without mutating.

### 6. Apply the edits

Write the proposed body to a temp file first (the same one used for
the diff in step 5 is fine), then point `gh pr edit` at it. Do not
use `<(cat <<'EOF' ... EOF)`; that form trips shell-expansion checks
and is brittle in agent shells.

```bash
# Title
gh pr edit <release-pr> --repo projectcalico/calico \
  --title "<new-title>"

# Body
cat > /tmp/release-pr.proposed <<'EOF'
<new-body>
EOF
gh pr edit <release-pr> --repo projectcalico/calico \
  --body-file /tmp/release-pr.proposed

# Labels (apply only the deltas computed in step 5)
gh pr edit <release-pr> --repo projectcalico/calico \
  --add-label "<labels-to-add>" \
  --remove-label "<labels-to-remove>"
```

Report the PR URL and a one-line summary of what was changed.

## PR conventions (used by both modes)

### Title

`[<branch-short>] <original-title>`

| Target branch | Prefix |
|---|---|
| `release-v3.31` | `[v3.31]` |
| `release-v3.32` | `[v3.32]` |

The prefix is derived by stripping `release-` from the branch name.

Multiple PRs: join stripped titles with `; `.

### Body

Three sections, in this order:

**Section 1: Cherry-pick history.**

```
**Cherry-pick history**
- Pick onto **<target-branch>**: projectcalico/calico#<PR>
```

For multiple PRs, use indented sub-bullets under the "Pick onto" line.

**Section 2: Original PR body.**

Separated from section 1 by a blank line. Use the original master PR
body verbatim with these adjustments:
- If it starts with a cherry-pick history header, strip that first
  line (keep any old pick bullets, they stack).
- Remove `## Todos` and `## Reminder for the reviewer` sections.
- Bare `#NNN` references in the body should ideally be prefixed with
  `projectcalico/calico` so they link correctly, but don't break the
  body trying to do this, it's a nice-to-have.

For multiple PRs, separate each with `---` and
`**Title** (projectcalico/calico#PR)`.

**Section 2.5: Conflict resolution notes (only if conflicts were resolved).**

If any conflicts were resolved during the cherry-pick, add a section
after the original body documenting what was resolved and how. This
helps reviewers understand what changed beyond the original PR. Format:

```
**Conflicts resolved:**
- `path/to/file.go`: Copyright year, took 2026
- `path/to/other.go`: Type name difference (`fooBar` → `FooBar`), kept the v3.32 form
```

Keep it concise, one line per file or group of files with the same
resolution. If all conflicts were the same type (e.g., all copyright
years), a single line is fine: "Copyright year conflicts in 5 files,
took 2026 for all."

**Section 3: Metadata (in a details expander).**

```html
<details>
<summary><b>Cherry-pick PR details</b></summary>

- **Original PR ID**: <PR-number(s)>
- **Original Commit SHA**: <first-10-chars>
</details>
```

Only the originating PR ID and commit SHA go here, the source/target
repos and target branch are properties of the PR itself (its base
repo and base branch), so don't restate them in the body.

### Labels

All original labels from the master PR, minus `cherry-pick-candidate`.
Comma-separated, deduplicated.

The release PR also needs one docs label (`docs-pr-required`,
`docs-completed`, or `docs-not-required`) and one release-note label
(`release-note-required` or `release-note-not-required`); preserve
whatever the master PR had.

## Notes

- The PR body content comes from the original master PR, don't
  rewrite it, just adjust formatting as described above.
- Never force-push without asking.
- If the user asks to target a release branch the skill doesn't
  recognise (older than the active set), confirm with the user before
  proceeding rather than guessing.
- In Mode B, never overwrite a substantially different body without
  showing the diff and getting confirmation. Edits should be additive
  (cherry-pick-history block, metadata expander, missing labels)
  wherever possible.
