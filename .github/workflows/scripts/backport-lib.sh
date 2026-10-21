#!/usr/bin/env bash
#
# Helpers sourced by both backport jobs, so Job B derives every fact itself
# instead of trusting Job A.

BACKPORT_BRANCH_PREFIX="auto-backport/"
# shellcheck disable=SC2034 # used by backport-apply.sh
BACKPORT_LABEL="auto-backport"

# Target branches from names on stdin: newest 3 GA lines, plus the newest EE
# pre-release (-N) until its GA branch exists.
backport_targets() {
  local names newest_xy pre=""
  names="$(cat)"
  newest_xy="$(grep -E '^release-calient-v[0-9]+\.[0-9]+(-[0-9]+)?$' <<<"$names" |
    sed -E 's/^release-calient-v([0-9]+\.[0-9]+).*/\1/' | sort -V | tail -1 || true)"
  if [ -n "$newest_xy" ] && ! grep -qx "release-calient-v${newest_xy}" <<<"$names"; then
    pre="$(grep -E "^release-calient-v${newest_xy//./\\.}-[0-9]+$" <<<"$names" | sort -V | tail -1 || true)"
  fi
  {
    [ -z "$pre" ] || echo "$pre"
    grep -E '^release-calient-v[0-9]+\.[0-9]+$' <<<"$names" | sort -V | tail -3 | sort -rV || true
    grep -E '^release-v[0-9]+\.[0-9]+$' <<<"$names" | sort -V | tail -3 | sort -rV || true
  } | grep . || true
}

# Test code only. CI config is excluded: a test fix must not change what CI runs.
backport_is_test_path() {
  case "$1" in
    .github/* | .semaphore/*) return 1 ;;
    hack/test/* | process/testing/*) return 0 ;;
  esac
  [[ "$1" =~ _test\.go$ ]] && return 0
  [[ "/$1" =~ /(ut|fv|e2e|test|tests|testutil|testutils|testdata)/ ]] && return 0
  return 1
}

# Succeeds when every path on stdin is test code and there is at least one.
backport_all_test_paths() {
  local f n=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    backport_is_test_path "$f" || return 1
    n=$((n + 1))
  done
  [ "$n" -gt 0 ]
}

# PR number from a merge or squash-merge subject; empty for a direct push.
backport_pr_of() {
  sed -nE 's/^Merge pull request #([0-9]+) from .*/\1/p; t; s/.*\(#([0-9]+)\)$/\1/p' <<<"$1"
}

# A merge commit picks against its first parent.
backport_pick_args() {
  if [ "$(git show --no-patch --format=%P "$1" | wc -w)" -ge 2 ]; then
    echo "-m 1 $1"
  else
    echo "$1"
  fi
}

# The diff a commit introduces against its first parent.
backport_commit_diff() {
  git diff --no-renames "${1}^1" "$1"
}

# Diff lines on stdin as "<path>\t<+|->\t<text>". Headers are tracked by state,
# so content starting with "--" survives.
backport_diff_lines() {
  awk '
    /^diff --git /    { hdr = 1; path = ""; next }
    hdr && /^--- /    { p = substr($0, 5); sub(/^a\//, "", p); if (p != "/dev/null") path = p; next }
    hdr && /^\+\+\+ / { p = substr($0, 5); sub(/^b\//, "", p); if (p != "/dev/null") path = p; next }
    /^@@/             { hdr = 0; next }
    hdr               { next }
    /^[+-]/           { print path "\t" substr($0, 1, 1) "\t" substr($0, 2) }
  '
}

# Changed lines in PICK that MASTER lacks. Paths are ignored because a branch
# may keep the test elsewhere.
backport_extra_lines() {
  local ml
  ml="$(mktemp)"
  backport_commit_diff "$2" | backport_diff_lines >"$ml"
  # Multiset difference: each master line cancels one equal pick line.
  backport_commit_diff "$1" | backport_diff_lines |
    awk -F'\t' 'NR == FNR { have[$2 "\t" $3]++; next }
      { k = $2 "\t" $3; if (have[k] > 0) have[k]--; else print }' "$ml" -
  rm -f "$ml"
}

# "<sha>\t<pr>" for master first-parent merges in (SINCE, UNTIL], oldest first.
backport_master_window() {
  local master="$1" since="$2" until="$3" sha subject pr
  git log --first-parent --reverse --format='%H%x09%s' \
    --since="@${since}" --until="@${until}" "$master" |
    while IFS=$'\t' read -r sha subject; do
      pr="$(backport_pr_of "$subject")"
      [ -z "$pr" ] || printf '%s\t%s\n' "$sha" "$pr"
    done
}

# Whether SHA is on BASE already: as an ancestor, a recorded pick, its PR
# number, or its patch-id.
backport_on_branch() {
  local sha="$1" pr="$2" base="$3" fork="$4" patch_ids="$5" pid
  git merge-base --is-ancestor "$sha" "$base" && return 0
  # Herestrings, not pipes: grep -q exiting early would fail the pipe under pipefail.
  grep -qF "cherry picked from commit ${sha}" <<<"$(git log --format=%B "${fork}..${base}")" && return 0
  grep -qE "\(#${pr}\)" <<<"$(git log --format=%s "${fork}..${base}")" && return 0
  pid="$(backport_commit_diff "$sha" | git patch-id --stable | cut -d' ' -f1)"
  [ -n "$pid" ] && grep -qxF "$pid" "$patch_ids"
}

# Patch-ids of FORK..BASE, one per line.
backport_patch_ids() {
  git log -p --no-merges --format='commit %H' "${1}..${2}" | git patch-id --stable | cut -d' ' -f1
}

# Open batch PR for BRANCH on REPO as "<number>\t<head ref>\t<head sha>", if any.
backport_open_batch() {
  local repo="$1" branch="$2"
  gh api "repos/${repo}/pulls?state=open&base=${branch}&per_page=100" \
    --jq ".[] | select(.head.repo.full_name == \"${repo}\" and (.head.ref | startswith(\"${BACKPORT_BRANCH_PREFIX}\")))
          | \"\(.number)\t\(.head.ref)\t\(.head.sha)\"" | head -1
}

# Short branch tag for titles and branch names: release-v3.33 -> v3.33,
# release-calient-v3.24-1 -> v3.24-1.
backport_short() {
  local b="${1#release-}"
  echo "${b#calient-}"
}
