#!/usr/bin/env bash

# Unit tests for build-pr-description() in hack/cherry-pick-pull.
# Run with:  bash hack/cherry-pick-pull_test.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/cherry-pick-pull"

PASS=0
FAIL=0

# assert_contains VAR NEEDLE [MESSAGE]
assert_contains() {
  local val="$1" needle="$2" msg="${3:-}"
  if [[ "$val" == *"$needle"* ]]; then
    return 0
  fi
  echo "FAIL${msg:+: $msg}"
  echo "  expected to contain: ${needle}"
  echo "  actual value:"
  echo "$val" | sed 's/^/    /'
  FAIL=$((FAIL + 1))
  return 1
}

# assert_not_contains VAR NEEDLE [MESSAGE]
assert_not_contains() {
  local val="$1" needle="$2" msg="${3:-}"
  if [[ "$val" != *"$needle"* ]]; then
    return 0
  fi
  echo "FAIL${msg:+: $msg}"
  echo "  expected NOT to contain: ${needle}"
  echo "  actual value:"
  echo "$val" | sed 's/^/    /'
  FAIL=$((FAIL + 1))
  return 1
}

# assert_equals ACTUAL EXPECTED [MESSAGE]
assert_equals() {
  local actual="$1" expected="$2" msg="${3:-}"
  if [[ "$actual" == "$expected" ]]; then
    return 0
  fi
  echo "FAIL${msg:+: $msg}"
  echo "  expected: $(printf '%q' "$expected")"
  echo "  actual:   $(printf '%q' "$actual")"
  FAIL=$((FAIL + 1))
  return 1
}

run_test() {
  local name="$1"
  # Reset outputs
  BUILD_TITLE=""
  BUILD_BODY=""
  BUILD_LABELS=""
  echo -n "  ${name}... "
}

pass() {
  echo "ok"
  PASS=$((PASS + 1))
}

###############################################################################
# Test 1: Fresh single pick — no cherry-pick history in source body
###############################################################################
run_test "fresh single pick"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "Fix widget rendering" )
PULL_BODIES=( "This PR fixes the widget rendering bug.

## Description
Some details here." )
PULL_LABELS=( "bug
docs-not-required" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

assert_equals "$BUILD_TITLE" "Fix widget rendering" "title" &&
assert_contains "$BUILD_BODY" "**Cherry-pick history**" "has header" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.14**: projectcalico/calico#100" "has bullet" &&
assert_contains "$BUILD_BODY" "This PR fixes the widget rendering bug." "has body" &&
assert_contains "$BUILD_LABELS" "bug" "has bug label" &&
assert_contains "$BUILD_LABELS" "docs-not-required" "has docs label" &&
assert_not_contains "$BUILD_LABELS" "cherry-pick-candidate" "no cherry-pick-candidate" &&
pass

###############################################################################
# Test 2: Re-pick with old ## heading format
###############################################################################
run_test "re-pick (old ## format)"

rel="release-v3.15"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "[v3.14] Fix widget rendering" )
PULL_BODIES=( '## Cherry-pick history
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug.' )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#200" )

build-pr-description

assert_equals "$BUILD_TITLE" "Fix widget rendering" "title strips old tag" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.15**: projectcalico/calico#200" "new bullet" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.14**: projectcalico/calico#100" "old bullet preserved" &&
assert_contains "$BUILD_BODY" "This PR fixes the widget rendering bug." "body preserved" &&
pass

###############################################################################
# Test 3: Re-pick with new **bold** heading format
###############################################################################
run_test "re-pick (new ** format)"

rel="release-v3.15"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "[v3.14] Fix widget rendering" )
PULL_BODIES=( '**Cherry-pick history**
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug.' )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#300" )

build-pr-description

assert_equals "$BUILD_TITLE" "Fix widget rendering" "title strips old tag" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.15**: projectcalico/calico#300" "new bullet" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.14**: projectcalico/calico#100" "old bullet preserved" &&
assert_contains "$BUILD_BODY" "This PR fixes the widget rendering bug." "body preserved" &&
pass

###############################################################################
# Test 4: Re-pick of a re-pick — multiple stacked bullet lines
###############################################################################
run_test "re-pick of a re-pick (stacked bullets)"

rel="release-v3.16"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "[v3.15] Fix widget rendering" )
PULL_BODIES=( '**Cherry-pick history**
- Pick onto **release-v3.15**: projectcalico/calico#300
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug.' )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#400" )

build-pr-description

assert_equals "$BUILD_TITLE" "Fix widget rendering" "title strips old tag" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.16**: projectcalico/calico#400" "newest bullet" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.15**: projectcalico/calico#300" "middle bullet" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.14**: projectcalico/calico#100" "oldest bullet" &&
assert_contains "$BUILD_BODY" "This PR fixes the widget rendering bug." "body preserved" &&
pass

###############################################################################
# Test 4b: Re-pick of a multi-PR pick — indented sub-bullets
###############################################################################
run_test "re-pick of multi-PR pick (indented bullets)"

rel="release-v3.15"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "[v3.14] Fix widget rendering; Update docs for widget" )
PULL_BODIES=( '**Cherry-pick history**
- Pick onto **release-v3.14**:
  - projectcalico/calico#100
  - projectcalico/calico#101

The actual PR body starts here.' )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#500" )

build-pr-description

assert_equals "$BUILD_TITLE" "Fix widget rendering; Update docs for widget" "title strips old tag" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.15**: projectcalico/calico#500" "new bullet" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.14**:" "old group bullet preserved" &&
assert_contains "$BUILD_BODY" "  - projectcalico/calico#100" "old sub-bullet 1 preserved" &&
assert_contains "$BUILD_BODY" "  - projectcalico/calico#101" "old sub-bullet 2 preserved" &&
assert_contains "$BUILD_BODY" "The actual PR body starts here." "body preserved" &&
assert_not_contains "$BUILD_BODY" "**Cherry-pick history**
- Pick onto **release-v3.15**: projectcalico/calico#500
- Pick onto **release-v3.14**:
  - projectcalico/calico#100
  - projectcalico/calico#101

- Pick onto **release-v3.14**:" "no duplicate old bullets in body" &&
pass

###############################################################################
# Test 5: Multi-PR pick
###############################################################################
run_test "multi-PR pick"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "Fix widget rendering" "Update docs for widget" )
PULL_BODIES=( "Widget fix body." "Docs update body." )
PULL_LABELS=( "bug" "docs-completed" )
PULLLINK=( "projectcalico/calico#100" "projectcalico/calico#101" )

build-pr-description

assert_equals "$BUILD_TITLE" "Fix widget rendering; Update docs for widget" "combined title" &&
assert_contains "$BUILD_BODY" "- Pick onto **release-v3.14**:" "group bullet" &&
assert_contains "$BUILD_BODY" "  - projectcalico/calico#100" "sub-bullet 1" &&
assert_contains "$BUILD_BODY" "  - projectcalico/calico#101" "sub-bullet 2" &&
assert_contains "$BUILD_BODY" "Widget fix body." "body 1" &&
assert_contains "$BUILD_BODY" "Docs update body." "body 2" &&
assert_contains "$BUILD_LABELS" "bug" "has bug label" &&
assert_contains "$BUILD_LABELS" "docs-completed" "has docs label" &&
pass

###############################################################################
# Test 6: Cross-repo pick — bare #123 refs get prefixed
###############################################################################
run_test "cross-repo pick (bare # refs prefixed)"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="tigera"
SRC_MAIN_REPO_NAME="calico-private"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "Fix issue" )
PULL_BODIES=( 'Fixes #42 and relates to #99.
Already prefixed: tigera/calico-private#50 should stay.' )
PULL_LABELS=( "bug" )
PULLLINK=( "tigera/calico-private#500" )

build-pr-description

assert_contains "$BUILD_BODY" "tigera/calico-private#42" "bare #42 prefixed" &&
assert_contains "$BUILD_BODY" "tigera/calico-private#99" "bare #99 prefixed" &&
assert_contains "$BUILD_BODY" "tigera/calico-private#50 should stay" "already-prefixed ref unchanged" &&
assert_not_contains "$BUILD_BODY" "tigera/calico-private#tigera" "no double-prefix" &&
pass

###############################################################################
# Test 7: EXTRA_LABELS and cherry-pick-candidate filtering
###############################################################################
run_test "EXTRA_LABELS and cherry-pick-candidate filtered"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS="extra-label"
META_BLOCK=""

PULL_TITLES=( "Some fix" )
PULL_BODIES=( "Body text." )
PULL_LABELS=( "bug
cherry-pick-candidate" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

assert_contains "$BUILD_LABELS" "bug" "has bug label" &&
assert_not_contains "$BUILD_LABELS" "cherry-pick-candidate" "cherry-pick-candidate filtered" &&
assert_contains "$BUILD_LABELS" "extra-label" "extra label appended" &&
pass

###############################################################################
# Test 8: Sections (Todos, Reminder for the reviewer) are stripped
###############################################################################
run_test "irrelevant sections stripped"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK=""

PULL_TITLES=( "A change" )
PULL_BODIES=( 'Main description.

## Todos
- [ ] something to do

## Reminder for the reviewer
Check the thing.

## Release note
Important note.' )
PULL_LABELS=( "enhancement" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

assert_contains "$BUILD_BODY" "Main description." "main body preserved" &&
assert_not_contains "$BUILD_BODY" "something to do" "Todos section stripped" &&
assert_not_contains "$BUILD_BODY" "Check the thing" "Reminder section stripped" &&
assert_contains "$BUILD_BODY" "Important note." "Release note section preserved" &&
pass

###############################################################################
# Test 9: META_BLOCK is included
###############################################################################
run_test "META_BLOCK included"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="projectcalico"
SRC_MAIN_REPO_NAME="calico"
DST_MAIN_REPO_ORG="projectcalico"
DST_MAIN_REPO_NAME="calico"
EXTRA_LABELS=""
META_BLOCK="<!-- meta: auto-generated -->"

PULL_TITLES=( "A change" )
PULL_BODIES=( "Body." )
PULL_LABELS=( "enhancement" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

assert_contains "$BUILD_BODY" "<!-- meta: auto-generated -->" "META_BLOCK present" &&
pass

###############################################################################
# Summary
###############################################################################
echo
echo "Results: ${PASS} passed, ${FAIL} failed"
if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
