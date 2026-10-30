#!/usr/bin/env bash

# Unit tests for ci-notify-recipients.sh.
# Run with:  bash .github/workflows/scripts/ci-notify-recipients_test.sh

set -o errexit
set -o nounset
set -o pipefail

if ! command -v jq >/dev/null; then
  echo "SKIP: ci-notify-recipients_test.sh needs jq"
  exit 0
fi

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ci-notify-recipients.sh"
PR_JSON="$(mktemp)"
trap 'rm -f "$PR_JSON"' EXIT

export CI_NOTIFY_MAP="alice:UALICE, bob:UBOB,carol:UCAROL"
export BOT_AUTHORS="marvin-tigera"
export ASSIGNEE_OWNED_LABELS="merge-oss-cherry-pick, some-future-label"

PASS=0
FAIL=0

# check NAME PR_JSON EXPECTED
check() {
  local name="$1" expected="$3" actual rc=0
  printf '%s' "$2" >"$PR_JSON"
  actual="$(bash "$SCRIPT" "$PR_JSON" 2>/dev/null)" || rc=$?
  if [[ $rc -eq 0 && "$actual" == "$expected" ]]; then
    PASS=$((PASS + 1))
  else
    echo "FAIL: $name (exit $rc)"
    echo "  expected: $(printf '%q' "$expected")"
    echo "  actual:   $(printf '%q' "$actual")"
    FAIL=$((FAIL + 1))
  fi
}

check "plain PR: author" \
  '{"login":"alice","labels":["bug"],"assignees":["bob"]}' \
  "UALICE"

check "bot PR with owned label: assignee" \
  '{"login":"marvin-tigera","labels":["merge-oss-cherry-pick"],"assignees":["bob"]}' \
  "UBOB"

check "human PR with owned label: still the author" \
  '{"login":"alice","labels":["merge-oss-cherry-pick"],"assignees":["bob"]}' \
  "UALICE"

check "bot PR without owned label: author (unmapped bot)" \
  '{"login":"marvin-tigera","labels":["bug"],"assignees":["bob"]}' \
  ""

check "any owned label in the list applies" \
  '{"login":"marvin-tigera","labels":["x","some-future-label"],"assignees":["carol"]}' \
  "UCAROL"

check "every mapped assignee, unmapped skipped" \
  '{"login":"marvin-tigera","labels":["merge-oss-cherry-pick"],"assignees":["carol","dave","bob"]}' \
  $'UBOB\nUCAROL'

check "bot PR, unassigned: falls back to author" \
  '{"login":"marvin-tigera","labels":["merge-oss-cherry-pick"],"assignees":[]}' \
  ""

check "logins match the map case-insensitively" \
  '{"login":"Marvin-Tigera","labels":["merge-oss-cherry-pick"],"assignees":["Bob"]}' \
  "UBOB"

ASSIGNEE_OWNED_LABELS="" check "no owned labels configured: author" \
  '{"login":"marvin-tigera","labels":["merge-oss-cherry-pick"],"assignees":["bob"]}' \
  ""

check "null labels on a bot PR: author" \
  '{"login":"marvin-tigera","labels":null,"assignees":["bob"]}' \
  ""

echo "${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
