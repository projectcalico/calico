---
name: cherry-pick-release
description: Cherry-pick a merged PR onto a Calico release branch using hack/cherry-pick-pull, or opt a PR out of a backport with /skip-backport. Use when the user wants to backport a fix to a release-vX.YY branch, says a PR is "not for backport to 3.xx", or asks about the cherry-pick process.
---

# Cherry-picking to Release Branches

**Merge the PR to `master` first.** Cherry-picks are made from the merged
commit, so a PR that is still open has nothing to pick.

Then run `hack/cherry-pick-pull` from the repo root:

```bash
SRC_UPSTREAM_REMOTE=origin DST_UPSTREAM_REMOTE=origin FORK_REMOTE=<your-remote> CHERRY_PICK=1 \
  ./hack/cherry-pick-pull origin/release-vX.YY <PR_NUMBER>
```

`FORK_REMOTE` is the remote for your personal fork — the script pushes the
cherry-pick branch there and opens the PR from it.

Bug fixes that should be backported are marked on the original PR with the
`cherry-pick-candidate` label.

## Release backporter

A nightly agent, the release backporter, judges merged `master` PRs and opens
one batch PR per owner and branch (label `release-backport`) for owners who
opted in. It tracks each master PR with these labels:

- `release-backport-eligible` (green): a patch-release fix that will be
  backported.
- `release-backport-ineligible` (red): not a patch-release fix. Add it
  yourself to keep a PR from being backported.
- `release-backport-done`: every live release branch has the fix or does not
  need it. The PR drops out of the agent's runs and merge cat's reminders.

The bar for a patch release: users can hit real harm with no reasonable
workaround, the buggy code exists on the branch, and the pick is safe. Not
safe: validation tightening, changed defaults or behavior, new dependencies or
a large prerequisite refactor. Features, perf work, refactors and test-only
changes are not backported. Code under `operator/` ships from tigera/operator.

To settle one branch, comment on the master PR with the command, then a reason
line:

```
/skip-backport release-vX.YY
<why it does not go to this branch>
```

Use `/backport-manual release-vX.YY` instead when someone ports it by hand.
Both the agent and merge cat honor these comments from org members.

A hand-made pick must name its original so the agent and merge cat see it.
`hack/cherry-pick-pull` does this already. Otherwise, keep the
`(cherry picked from commit <sha>)` line or add `Backports #<PR>` to the pick
PR's body. Closing a `release-backport` batch PR without merging rejects its
fixes on that branch for good.

## Skipping a backport

The merge-queue bot (`tigera/merge-queue-bot`, `backport_reminders.go`) asks
about each live release branch for a `cherry-pick-candidate` PR. To opt out of
a branch, comment on the PR:

    /skip-backport release-v3.32

- Separate several branches with spaces or commas.
- Put the command on its own line. Text before it on the same line is ignored.
- Only the PR author's comments count.
- Each token must be a full branch name (`release-v3.32`). Tokens such as
  `3.32` or `release-v3.x` are ignored, and so is a bare `/skip-backport`.
- It works per branch. There is no "skip all"; list every branch.
- Don't use labels to say "not for branch X". Labels apply to the whole PR.

Post it with the REST API:
`gh api repos/projectcalico/calico/issues/<PR>/comments -f body='/skip-backport release-v3.32'`
