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

# --- do_generate -----------------------------------------------------------
# Stub make: with MAKE_CHANGES=1 it mimics the generators editing a tracked
# file, adding an untracked one, and dropping an ignored build artifact; with 0
# it is a no-op. Idempotent, so do_generate's two make calls are safe.
MAKE_CHANGES=0
make() {
  [ "$MAKE_CHANGES" = "1" ] || return 0
  printf 'regenerated\n' > generated/zz.go
  printf 'new\n' > generated/new_gen.go
  mkdir -p build && printf 'junk\n' > build/artifact
}

# A finalized pick: a base commit holding .gitignore, then the pick commit with
# the picked source and a tracked generated file.
gen_repo() {
  local d; d="$(mktemp -d)"
  ( cd "$d"
    git init -q
    git config user.email t@t; git config user.name t
    printf 'build/\n' > .gitignore
    git add .gitignore && git commit -q -m base
    mkdir generated
    printf 'orig\n' > generated/zz.go
    printf 'src\n' > pick_src.go
    git add generated/zz.go pick_src.go && git commit -q -m "pick commit" )
  echo "$d"
}

committed_files() { git -C "$1" show --name-only --pretty=format: HEAD | sed '/^$/d' | sort | tr '\n' ' '; }

# Generators change files: amend the pick, union the allowlist, skip the ignored file.
MAKE_CHANGES=1
WORKDIR="$(gen_repo)"; PICK_PATHS_FILE="$(mktemp)"; printf 'pick_src.go\n' > "$PICK_PATHS_FILE"
GEN_OUT="$(GENERATE_TOKEN=x do_generate 2>&1)"
check "change: generate=done"        "$(grep -c 'generate=done' <<<"$GEN_OUT")" "1"
check "change: worktree clean"       "$(git -C "$WORKDIR" status --porcelain)" ""
check "change: generated committed"  "$(committed_files "$WORKDIR")" "generated/new_gen.go generated/zz.go pick_src.go "
check "change: allowlist unioned"    "$(sort "$PICK_PATHS_FILE" | tr '\n' ' ')" "generated/new_gen.go generated/zz.go pick_src.go "

# No generator change: noop, the pick commit and the allowlist are untouched.
MAKE_CHANGES=0
WORKDIR="$(gen_repo)"; PICK_PATHS_FILE="$(mktemp)"; printf 'pick_src.go\n' > "$PICK_PATHS_FILE"
BEFORE_HEAD="$(git -C "$WORKDIR" rev-parse HEAD)"
NOOP_OUT="$(GENERATE_TOKEN=x do_generate 2>&1)"
check "noop: generate=noop"   "$(grep -c 'generate=noop' <<<"$NOOP_OUT")" "1"
check "noop: HEAD untouched"   "$(git -C "$WORKDIR" rev-parse HEAD)" "$BEFORE_HEAD"
check "noop: allowlist kept"   "$(cat "$PICK_PATHS_FILE")" "pick_src.go"

echo "${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
