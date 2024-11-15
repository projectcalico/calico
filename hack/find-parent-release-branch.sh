#!/bin/bash

set -e

best_count=1000000
best=""

: "${release_prefix:=release-v}"
: "${git_remote:=projectcalico/calico}"

remote=$(git remote -v | grep "${git_remote}.*fetch" | cut -f1 )
echo "Git remote: $git_remote -> ${remote}" >&2

for ref in $(git for-each-ref --format='%(refname:short)' refs/remotes/${remote} | \
             grep --perl "${remote}/master$|${remote}/${release_prefix}[3-9]\.[2-9].*" ); do
  count=$(git rev-list --count $(git merge-base $ref HEAD)..HEAD)
  if [[ "$count" -lt "$best_count" ]]; then
    best_count=$count
    best=$ref
  fi
done

echo $best
