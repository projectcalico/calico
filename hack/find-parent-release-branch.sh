#!/bin/bash

best_count=1000000
best=""
for ref in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin | grep --perl 'origin/master$|origin/release-v[3-9]\.[2-9].*' ); do 
  count=$(git rev-list --count $(git merge-base $ref HEAD)..HEAD)
  if [[ "$count" -lt "$best_count" ]]; then
    best_count=$count
    best=$ref
  fi
done

echo $best
