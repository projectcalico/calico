#!/bin/bash

set -e

best_count=1000000
best=""

: "${release_prefix:=release-v}"
: "${git_repo_slug:=projectcalico/calico}"

current_branch=$(git branch --show-current)

# Some of our team members use "tigera" in their github usernames, which breaks
# this script for specifically those members when `git_repo_slug` starts with `tigera`;
# for example, for `tigera/somerepository`. This results in us fetching multiple
# lines of results as multiple lines match, which breaks the script.
#
#                                ┌────────this───────┐
# Expected match: git@github.com:tigera/somerepository.git
#
#                                         ┌─────also this─────┐
# Unexpected match: git@github.com:userbootigera/somerepository.git
#
# We can't just grab the first or last line because we don't know what order the
# remotes will be in, nor what actual format the remote URL will be in, so we
# just exclude matches with any alpha character in front of it.

echo "[debug] Trying to detect base branch by looking for most similar branch" >&2

remote=$(git remote -v | grep "[^a-zA-Z0-9]${git_repo_slug}.*fetch" | cut -f1 )

if [[ -z "${remote}" ]]; then
  echo "[error] Could not detect a git remote for ${git_repo_slug}; stop" >&2
  exit 1
fi

# If we're running in a CI environment...
if [[ -v CI ]]; then
  # Do we have a fetch that references multiple branches?
  if git config get remote.origin.fetch | fgrep -q "*"; then
    echo "[debug] We seem to be configured to fetch all branches" >&2
  else
    echo "[debug] We don't seem to be configured to fetch all branches; fixing and re-fetching..." >&2
    git config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"
    git fetch --all --quiet
  fi # git config
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
