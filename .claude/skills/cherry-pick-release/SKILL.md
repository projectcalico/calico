---
name: cherry-pick-release
description: Cherry-pick a merged PR onto a Calico release branch using hack/cherry-pick-pull. Use when the user wants to backport a fix to a release-vX.YY branch or asks about the cherry-pick process.
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
