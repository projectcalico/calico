#!/bin/bash

set -e

best_count=1000000
best=""

: "${release_prefix:=release-v}"
: "${git_repo_slug:=projectcalico/calico}"

# Find the appropriate remote, handling common forms of git URL:
#
#  -  proto://github.com/foo/bar.git
#  -  git@github.com:foo/bar.git
#
#  And avoiding matching prefixes of the desired slug:
#
#   Match:  git@github.com:tigera/somerepository.git
#   But not: git@github.com:userbootigera/somerepository.git
echo "[debug] Trying to detect base branch by looking for most similar branch" >&2

remote=$(git remote -v | grep "[:/]${git_repo_slug}.*fetch" | cut -f1 )

if [[ -z "${remote}" ]]; then
  echo "[error] Could not detect a git remote for ${git_repo_slug}; stop" >&2
  exit 1
fi

# If we're running in a CI environment...
if [[ -v CI ]]; then
  echo "[debug] Running in CI, so we're inspecting the git remotes" >&2
  # Do we have a fetch that references multiple branches?
  for remote in $(git remote); do
    if git config get remote.${remote}.fetch | fgrep -q "*"; then
      echo "[debug] Remote ${remote} seems to be configured to fetch all branches" >&2
    else
      echo "[debug] Remote ${remote} doesn't seem to be configured to fetch all branches; fixing..." >&2
      echo "[debug] Updating remote ${remote}" >&2
      git config remote.${remote}.fetch "+refs/heads/*:refs/remotes/${remote}/*"
    fi # git config
  done
  git fetch --all --quiet
fi # -v CI

echo "[debug] Git remote: ${git_repo_slug} -> ${remote}" >&2

for ref in $(git for-each-ref --format='%(refname:short)' refs/remotes/${remote} | \
             grep --perl "${remote}/master$|${remote}/${release_prefix}[3-9]\.[2-9].*" ); do
  count=$(git rev-list --count $(git merge-base $ref HEAD)..HEAD)
  if [[ "$count" -lt "$best_count" ]]; then
    best_count=$count
    best=$ref
  fi
done

echo "[debug] Found best result ${best} with a difference of ${count}" >&2
echo $best
