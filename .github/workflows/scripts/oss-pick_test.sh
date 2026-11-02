#!/usr/bin/env bash

# Unit tests for assign_pr() in oss-pick.sh.
# Run with:  bash .github/workflows/scripts/oss-pick_test.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_REPO=projectcalico/calico
TARGET_REPO=tigera/calico-private
TARGET_BRANCH=master
PR_NUMBER=123
MERGE_SHA=0123456789abcdef0123456789abcdef01234567
source "${SCRIPT_DIR}/oss-pick.sh"

PASS=0
FAIL=0
# assign_pr calls gh inside $(...), so the stub logs to a file.
GH_LOG="$(mktemp)"
trap 'rm -f "$GH_LOG"' EXIT
# What the stubbed assignees endpoint reports back; GitHub silently drops a
# login it cannot assign, so a test sets this to "" to model that.
GH_ASSIGNED=""
GH_EXIT=0

gh() {
  echo "$*" >>"$GH_LOG"
  [ "$GH_EXIT" -eq 0 ] || return "$GH_EXIT"
  [ -z "$GH_ASSIGNED" ] || echo "$GH_ASSIGNED"
}

check() {
  local name="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    PASS=$((PASS + 1))
  else
    echo "FAIL: $name"
    echo "  expected: $(printf '%q' "$expected")"
    echo "  actual:   $(printf '%q' "$actual")"
    FAIL=$((FAIL + 1))
  fi
}

run() {
  : >"$GH_LOG"
  RC=0
  OUT="$(assign_pr https://github.com/tigera/calico-private/pull/42 2>&1)" || RC=$?
  GH_CALLS="$(cat "$GH_LOG")"
}

URL_CALL="api repos/tigera/calico-private/issues/42/assignees -f assignees[]="

ASSIGN_CALL="${URL_CALL}alice --jq .assignees[].login"

ASSIGNEE=alice GH_ASSIGNED=alice GH_EXIT=0
run
check "assigns the owner" "$GH_CALLS" "$ASSIGN_CALL"
check "assigned: no warning" "$OUT" ""

# Someone assigned by hand stays; only the owner's presence matters.
ASSIGNEE=alice GH_ASSIGNED=$'carol\nalice'
run
check "alongside an existing assignee: no warning" "$OUT" ""

# Nobody to assign: no API call, no failure.
ASSIGNEE="" GH_ASSIGNED=""
run
check "no owner: no call" "$GH_CALLS" ""
check "no owner: rc" "$RC" "0"
check "no owner: notice" "$OUT" "::notice::no assignee for https://github.com/tigera/calico-private/pull/42"

# GitHub accepts the call but drops an unassignable login, leaving only
# whoever was assigned already.
ASSIGNEE=alice GH_ASSIGNED=carol
run
check "dropped login: rc" "$RC" "0"
check "dropped login: warns" "$OUT" "::warning::alice cannot be assigned on tigera/calico-private; not assigned to https://github.com/tigera/calico-private/pull/42"

# An API failure must not fail the step that already opened the PR.
ASSIGNEE=alice GH_ASSIGNED=alice GH_EXIT=1
run
check "api error: rc" "$RC" "0"
check "api error: warns" "$OUT" "::warning::could not assign alice to https://github.com/tigera/calico-private/pull/42"
GH_EXIT=0

echo "${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
