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
  # Reset outputs and defaults
  NEW_PR_TITLE=""
  NEW_PR_BODY=""
  NEW_PR_LABELS=""
  EXTRA_LABELS=""
  META_BLOCK=""
  PULL_SHAS=()
  SRC_MAIN_REPO_ORG="projectcalico"
  SRC_MAIN_REPO_NAME="calico"
  DST_MAIN_REPO_ORG="projectcalico"
  DST_MAIN_REPO_NAME="calico"
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
PULL_TITLES=( "Fix widget rendering" )
PULL_BODIES=( "This PR fixes the widget rendering bug.

## Description
Some details here." )
PULL_LABELS=( "bug
docs-not-required" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug.

## Description
Some details here.
"
assert_equals "$NEW_PR_TITLE" "Fix widget rendering" "title" &&
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
assert_equals "$NEW_PR_LABELS" "bug,docs-not-required" "labels" &&
pass

###############################################################################
# Test 2: Re-pick with old ## heading format
###############################################################################
run_test "re-pick (old ## format)"

rel="release-v3.15"
PULL_TITLES=( "[v3.14] Fix widget rendering" )
PULL_BODIES=( "## Cherry-pick history
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug." )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#200" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.15**: projectcalico/calico#200
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug.
"
assert_equals "$NEW_PR_TITLE" "Fix widget rendering" "title" &&
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 3: Re-pick with new **bold** heading format
###############################################################################
run_test "re-pick (new ** format)"

rel="release-v3.15"
PULL_TITLES=( "[v3.14] Fix widget rendering" )
PULL_BODIES=( "**Cherry-pick history**
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug." )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#300" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.15**: projectcalico/calico#300
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug.
"
assert_equals "$NEW_PR_TITLE" "Fix widget rendering" "title" &&
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 4: Re-pick of a re-pick — multiple stacked bullet lines
###############################################################################
run_test "re-pick of a re-pick (stacked bullets)"

rel="release-v3.16"
PULL_TITLES=( "[v3.15] Fix widget rendering" )
PULL_BODIES=( "**Cherry-pick history**
- Pick onto **release-v3.15**: projectcalico/calico#300
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug." )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#400" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.16**: projectcalico/calico#400
- Pick onto **release-v3.15**: projectcalico/calico#300
- Pick onto **release-v3.14**: projectcalico/calico#100

This PR fixes the widget rendering bug.
"
assert_equals "$NEW_PR_TITLE" "Fix widget rendering" "title" &&
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 4b: Re-pick of a multi-PR pick — indented sub-bullets
###############################################################################
run_test "re-pick of multi-PR pick (indented bullets)"

rel="release-v3.15"
PULL_TITLES=( "[v3.14] Fix widget rendering; Update docs for widget" )
PULL_BODIES=( "**Cherry-pick history**
- Pick onto **release-v3.14**:
  - projectcalico/calico#100
  - projectcalico/calico#101

The actual PR body starts here." )
PULL_LABELS=( "bug" )
PULLLINK=( "projectcalico/calico#500" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.15**: projectcalico/calico#500
- Pick onto **release-v3.14**:
  - projectcalico/calico#100
  - projectcalico/calico#101

The actual PR body starts here.
"
assert_equals "$NEW_PR_TITLE" "Fix widget rendering; Update docs for widget" "title" &&
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 5: Multi-PR pick
###############################################################################
run_test "multi-PR pick"

rel="release-v3.14"
PULL_TITLES=( "Fix widget rendering" "Update docs for widget" )
PULL_BODIES=( "Widget fix body." "Docs update body." )
PULL_LABELS=( "bug" "docs-completed" )
PULLLINK=( "projectcalico/calico#100" "projectcalico/calico#101" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.14**:
  - projectcalico/calico#100
  - projectcalico/calico#101

---
**Fix widget rendering** (projectcalico/calico#100)
Widget fix body.
---
**Update docs for widget** (projectcalico/calico#101)
Docs update body.
"
assert_equals "$NEW_PR_TITLE" "Fix widget rendering; Update docs for widget" "title" &&
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
assert_equals "$NEW_PR_LABELS" "bug,docs-completed" "labels" &&
pass

###############################################################################
# Test 6: Cross-repo pick — bare #123 refs get prefixed
###############################################################################
run_test "cross-repo pick (bare # refs prefixed)"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="tigera"
SRC_MAIN_REPO_NAME="calico-private"
PULL_TITLES=( "Fix issue" )
PULL_BODIES=( "Fixes #42 and relates to #99.
Already prefixed: tigera/calico-private#50 should stay." )
PULL_LABELS=( "bug" )
PULLLINK=( "tigera/calico-private#500" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.14**: tigera/calico-private#500

Fixes tigera/calico-private#42 and relates to tigera/calico-private#99.
Already prefixed: tigera/calico-private#50 should stay.
"
assert_equals "$NEW_PR_TITLE" "Fix issue" "title" &&
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 7: EXTRA_LABELS and cherry-pick-candidate filtering
###############################################################################
run_test "EXTRA_LABELS and cherry-pick-candidate filtered"

rel="release-v3.14"
EXTRA_LABELS="extra-label"
PULL_TITLES=( "Some fix" )
PULL_BODIES=( "Body text." )
PULL_LABELS=( "bug
cherry-pick-candidate" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

assert_equals "$NEW_PR_LABELS" "bug,extra-label" "labels" &&
pass

###############################################################################
# Test 8: Sections (Todos, Reminder for the reviewer) are stripped
###############################################################################
run_test "irrelevant sections stripped"

rel="release-v3.14"
PULL_TITLES=( "A change" )
PULL_BODIES=( "Main description.

## Todos
- [ ] something to do

## Reminder for the reviewer
Check the thing.

## Release note
Important note." )
PULL_LABELS=( "enhancement" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.14**: projectcalico/calico#100

Main description.

## Release note
Important note.
"
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 9: META_BLOCK is included
###############################################################################
run_test "META_BLOCK included"

rel="release-v3.14"
META_BLOCK="<!-- meta: auto-generated -->"
PULL_TITLES=( "A change" )
PULL_BODIES=( "Body." )
PULL_LABELS=( "enhancement" )
PULLLINK=( "projectcalico/calico#100" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.14**: projectcalico/calico#100

Body.
<!-- meta: auto-generated -->"
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 10: release-note-required wins over release-note-not-required
###############################################################################
run_test "release-note-required wins in a multi-PR pick"

rel="release-v3.14"
PULL_TITLES=( "Test lib cleanup" "Fix widget rendering" )
PULL_BODIES=( "Test body." "Fix body." )
PULL_LABELS=( "docs-not-required
release-note-not-required" "docs-not-required
release-note-required
cherry-pick-candidate" )
PULLLINK=( "projectcalico/calico#100" "projectcalico/calico#101" )

build-pr-description

assert_equals "$NEW_PR_LABELS" "docs-not-required,release-note-required" "labels" &&
pass

###############################################################################
# Test 11: release-note-not-required kept when no PR needs a release note
###############################################################################
run_test "release-note-not-required kept when unanimous"

rel="release-v3.14"
PULL_TITLES=( "Test lib cleanup" "CI tweak" )
PULL_BODIES=( "Test body." "CI body." )
PULL_LABELS=( "release-note-not-required" "release-note-not-required" )
PULLLINK=( "projectcalico/calico#100" "projectcalico/calico#101" )

build-pr-description

assert_equals "$NEW_PR_LABELS" "release-note-not-required" "labels" &&
pass

###############################################################################
# Test 12: Merge Cat details block generated for a single merged PR
###############################################################################
run_test "details block for a single PR"

rel="release-v3.14"
PULL_TITLES=( "A change" )
PULL_BODIES=( "Body." )
PULL_LABELS=( "enhancement" )
PULLLINK=( "projectcalico/calico#100" )
PULL_SHAS=( "0123456789abcdef0123456789abcdef01234567" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.14**: projectcalico/calico#100

Body.
<details>
<summary><b>Cherry-Pick PR details</b></summary>

- **Original PR ID**: 100
- **Original Commit SHA**: 0123456789
- **Source Repo**: \`projectcalico/calico\`
- **Target Repo**: \`projectcalico/calico\`
- **Target Branch**: \`release-v3.14\`
</details>"
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Test 13: Merge Cat details block generated for a multi-PR pick
###############################################################################
run_test "details block for a multi-PR pick"

rel="release-v3.14"
SRC_MAIN_REPO_ORG="tigera"
SRC_MAIN_REPO_NAME="calico-private"
PULL_TITLES=( "First" "Second" )
PULL_BODIES=( "One." "Two." )
PULL_LABELS=( "bug" "bug" )
PULLLINK=( "tigera/calico-private#100" "tigera/calico-private#101" )
PULL_SHAS=( "aaaaaaaaaaaaaaaaaaaa" "bbbbbbbbbbbbbbbbbbbb" )

build-pr-description

expected_meta="<details>
<summary><b>Cherry-Pick PR details</b></summary>

- **Original PR IDs**: #100, #101
- **Original Commit SHAs**: aaaaaaaaaa, bbbbbbbbbb
- **Source Repo**: \`tigera/calico-private\`
- **Target Repo**: \`projectcalico/calico\`
- **Target Branch**: \`release-v3.14\`
</details>"
assert_equals "${NEW_PR_BODY#*$'\n'Two.$'\n'}" "$expected_meta" "details block" &&
pass

###############################################################################
# Test 14: No details block when any picked PR is unmerged
###############################################################################
run_test "no details block for an unmerged PR"

rel="release-v3.14"
PULL_TITLES=( "First" "Second" )
PULL_BODIES=( "One." "Two." )
PULL_LABELS=( "bug" "bug" )
PULLLINK=( "projectcalico/calico#100" "projectcalico/calico#101" )
PULL_SHAS=( "aaaaaaaaaaaaaaaaaaaa" "" )

build-pr-description

assert_equals "${NEW_PR_BODY##*$'\n'}" "" "body ends without a details block" &&
assert_equals "$(grep -c 'Original' <<<"$NEW_PR_BODY")" "0" "no Original lines" &&
pass

###############################################################################
# Test 15: META_BLOCK replaces the generated details block
###############################################################################
run_test "META_BLOCK overrides the details block"

rel="release-v3.14"
META_BLOCK="custom block"
PULL_TITLES=( "A change" )
PULL_BODIES=( "Body." )
PULL_LABELS=( "enhancement" )
PULLLINK=( "projectcalico/calico#100" )
PULL_SHAS=( "0123456789abcdef" )

build-pr-description

expected_body="**Cherry-pick history**
- Pick onto **release-v3.14**: projectcalico/calico#100

Body.
custom block"
assert_equals "$NEW_PR_BODY" "$expected_body" "body" &&
pass

###############################################################################
# Summary
###############################################################################
echo
echo "Results: ${PASS} passed, ${FAIL} failed"
if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
