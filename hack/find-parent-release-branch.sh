#!/bin/bash

set -e

best_count=1000000
best=""


if [[ -v CI ]]; then
  # In (Semaphore) CI branch runs, we only have the current branch as part of our fetch,
  # so we can't find a parent release branch.
  #
  # We need to override the default fetch to include all branches and then re-fetch and
  # unshallow the repo.
  echo "Running in CI, re-fetching all branches" >&2
  git config set remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'

  # We want to unshallow, but passing --unshallow to git fetch will fail if the repo is not shallow.
  # So we try to unshallow first, and if that fails, we just do a normal fetch.
  git fetch --unshallow || git fetch
fi

: "${release_prefix:=release-v}"
: "${git_repo_slug:=projectcalico/calico}"

remote=$(git remote -v | grep "${git_repo_slug}.*fetch" | cut -f1 )
echo "Git remote: ${git_repo_slug} -> ${remote}" >&2

for ref in $(git for-each-ref --format='%(refname:short)' refs/remotes/${remote} | \
             grep --perl "${remote}/master$|${remote}/${release_prefix}[3-9]\.[2-9].*" ); do
  if git merge-base "$ref" HEAD > /dev/null; then
         count=$(git rev-list --count "$(git merge-base $ref HEAD)"..HEAD)
         if [[ "$count" -lt "$best_count" ]]; then
           best_count=$count
           best=$ref
         fi
  fi
done

echo $best
