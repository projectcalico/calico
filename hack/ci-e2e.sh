#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Walk up from SCRIPT_DIR to find repo root (contains go.mod at top level).
REPO_ROOT="$SCRIPT_DIR"
while [[ "$REPO_ROOT" != "/" && ! -f "$REPO_ROOT/go.mod" ]]; do
    REPO_ROOT="$(dirname "$REPO_ROOT")"
done
if [[ ! -f "$REPO_ROOT/go.mod" ]]; then
    echo "error: could not find repo root (no go.mod found)" >&2
    exit 1
fi

PROFILES_FILE="$REPO_ROOT/.github/e2e-profiles.yaml"
PATH_LABELS_FILE="$REPO_ROOT/.github/e2e-path-labels.yaml"

# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------
ARG_PR=""
ARG_PROFILE=""
ARG_LABEL_FILTER=""
HELP=0

for arg in "$@"; do
    case "$arg" in
        --pr=*)         ARG_PR="${arg#--pr=}" ;;
        --profile=*)    ARG_PROFILE="${arg#--profile=}" ;;
        --label-filter=*) ARG_LABEL_FILTER="${arg#--label-filter=}" ;;
        --help|-h)      HELP=1 ;;
        *)
            echo "error: unknown flag: $arg" >&2
            echo "Usage: $0 [--pr=NUM] [--profile=NAME] [--label-filter=EXPR]" >&2
            exit 1
            ;;
    esac
done

if [[ $HELP -eq 1 ]]; then
    cat <<'EOF'
Usage: hack/ci-e2e.sh [--pr=NUM] [--profile=NAME] [--label-filter=EXPR]

Triggers e2e tests on a pull request by posting a /e2e comment.

Flags:
  --pr=NUM              PR number (auto-detected from current branch if omitted)
  --profile=NAME        Test profile (interactive menu if omitted)
  --label-filter=EXPR   Ginkgo label-filter expression (prompted if omitted)
  --help                Show this help

Examples:
  hack/ci-e2e.sh --profile=bpf-gcp --label-filter="Feature:BPF" --pr=12345
  make ci-e2e PROFILE=bpf-gcp LABEL_FILTER="Feature:BPF"
  make ci-e2e   # fully interactive
EOF
    exit 0
fi

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
if ! command -v gh &>/dev/null; then
    echo "error: 'gh' CLI is required but not found. Install from https://cli.github.com/" >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "error: 'python3' is required but not found." >&2
    exit 1
fi

if [[ ! -f "$PROFILES_FILE" ]]; then
    echo "error: profiles file not found: $PROFILES_FILE" >&2
    exit 1
fi

if [[ ! -f "$PATH_LABELS_FILE" ]]; then
    echo "error: path-labels file not found: $PATH_LABELS_FILE" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# PR auto-detection
# ---------------------------------------------------------------------------
if [[ -z "$ARG_PR" ]]; then
    PR_JSON="$(gh pr view --json number,headRefName 2>/dev/null || true)"
    if [[ -z "$PR_JSON" ]]; then
        echo "error: could not detect a PR for the current branch. Use --pr=NUM to specify one." >&2
        exit 1
    fi
    ARG_PR="$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['number'])" <<< "$PR_JSON")"
    PR_BRANCH="$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['headRefName'])" <<< "$PR_JSON")"
    echo "Detected PR #${ARG_PR} (${PR_BRANCH})"
fi

PR="$ARG_PR"

# ---------------------------------------------------------------------------
# Load profiles from YAML using python3
# ---------------------------------------------------------------------------
PROFILES_JSON="$(python3 - <<PYEOF
import sys, json
try:
    import yaml
except ImportError:
    # Minimal YAML parser for our simple flat structure
    import re
    profiles = {}
    current = None
    with open("$PROFILES_FILE") as f:
        for line in f:
            m = re.match(r'^  (\S+):$', line)
            if m:
                current = m.group(1)
                profiles[current] = {}
                continue
            if current:
                m = re.match(r'^    description:\s+"(.+)"', line)
                if m:
                    profiles[current]['description'] = m.group(1)
    print(json.dumps(profiles))
    sys.exit(0)

with open("$PROFILES_FILE") as f:
    data = yaml.safe_load(f)
print(json.dumps(data.get('profiles', {})))
PYEOF
)"

# Build ordered list of profile names and descriptions.
PROFILE_NAMES=()
PROFILE_DESCS=()
while IFS=$'\t' read -r name desc; do
    PROFILE_NAMES+=("$name")
    PROFILE_DESCS+=("$desc")
done < <(python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
for name, info in data.items():
    print(name + '\t' + info.get('description', ''))
" <<< "$PROFILES_JSON")

if [[ ${#PROFILE_NAMES[@]} -eq 0 ]]; then
    echo "error: no profiles found in $PROFILES_FILE" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Profile selection
# ---------------------------------------------------------------------------
PROFILE=""

if [[ -n "$ARG_PROFILE" ]]; then
    # Validate the provided profile.
    for name in "${PROFILE_NAMES[@]}"; do
        if [[ "$name" == "$ARG_PROFILE" ]]; then
            PROFILE="$ARG_PROFILE"
            break
        fi
    done
    if [[ -z "$PROFILE" ]]; then
        echo "error: unknown profile '$ARG_PROFILE'. Valid profiles: ${PROFILE_NAMES[*]}" >&2
        exit 1
    fi
else
    echo ""
    echo "Select profile:"
    for i in "${!PROFILE_NAMES[@]}"; do
        printf "  %d) %-20s - %s\n" "$((i+1))" "${PROFILE_NAMES[$i]}" "${PROFILE_DESCS[$i]}"
    done
    while true; do
        printf "> "
        read -r selection
        # Accept a number.
        if [[ "$selection" =~ ^[0-9]+$ ]]; then
            idx=$((selection - 1))
            if [[ $idx -ge 0 && $idx -lt ${#PROFILE_NAMES[@]} ]]; then
                PROFILE="${PROFILE_NAMES[$idx]}"
                break
            fi
        fi
        # Accept a name directly.
        for name in "${PROFILE_NAMES[@]}"; do
            if [[ "$name" == "$selection" ]]; then
                PROFILE="$selection"
                break 2
            fi
        done
        echo "Invalid selection. Enter a number (1-${#PROFILE_NAMES[@]}) or a profile name."
    done
fi

# ---------------------------------------------------------------------------
# Path-based label suggestion
# ---------------------------------------------------------------------------
SUGGESTED_LABEL=""
SUGGESTION_REASON=""

CHANGED_FILES="$(gh pr diff "$PR" --name-only 2>/dev/null || true)"

if [[ -n "$CHANGED_FILES" ]]; then
    # Use python3 with fnmatch to match paths against rules.
    SUGGESTION="$(python3 - <<PYEOF
import json, sys, fnmatch

try:
    import yaml
    with open("$PATH_LABELS_FILE") as f:
        data = yaml.safe_load(f)
    rules = data.get('path_labels', [])
except ImportError:
    # Minimal parser fallback — reads what we need from the structured YAML.
    import re
    rules = []
    current = {}
    with open("$PATH_LABELS_FILE") as f:
        content = f.read()
    # Use json output from a structured parse isn't feasible without yaml;
    # emit empty and rely on the "no suggestion" path.
    rules = []

profile = "$PROFILE"
changed = """$CHANGED_FILES""".strip().splitlines()

collected_labels = []
reasons = []
for rule in rules:
    rule_profiles = rule.get('profiles', [])
    if profile not in rule_profiles:
        continue
    rule_labels = rule.get('labels', '')
    rule_reason = rule.get('reason', '')
    rule_paths = rule.get('paths', [])
    for f in changed:
        matched = any(fnmatch.fnmatch(f, pat) for pat in rule_paths)
        if matched:
            if rule_labels and rule_labels not in collected_labels:
                collected_labels.append(rule_labels)
            if rule_reason and rule_reason not in reasons:
                reasons.append(rule_reason)
            break

if collected_labels:
    print("LABELS:" + " || ".join(collected_labels))
    print("REASON:" + ", ".join(reasons))
PYEOF
    )"

    if [[ -n "$SUGGESTION" ]]; then
        SUGGESTED_LABEL="$(grep '^LABELS:' <<< "$SUGGESTION" | sed 's/^LABELS://' || true)"
        SUGGESTION_REASON="$(grep '^REASON:' <<< "$SUGGESTION" | sed 's/^REASON://' || true)"
        if [[ -n "$SUGGESTED_LABEL" && -n "$SUGGESTION_REASON" ]]; then
            echo ""
            echo "Changed files suggest: ${SUGGESTED_LABEL} (${SUGGESTION_REASON})"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Label filter prompt
# ---------------------------------------------------------------------------
LABEL_FILTER=""

if [[ -n "$ARG_LABEL_FILTER" ]]; then
    LABEL_FILTER="$ARG_LABEL_FILTER"
else
    echo ""
    if [[ -n "$SUGGESTED_LABEL" ]]; then
        printf "Label filter [%s]:\n> " "$SUGGESTED_LABEL"
    else
        printf "Label filter (leave blank to run all tests):\n> "
    fi
    read -r user_label
    if [[ -z "$user_label" && -n "$SUGGESTED_LABEL" ]]; then
        LABEL_FILTER="$SUGGESTED_LABEL"
    else
        LABEL_FILTER="$user_label"
    fi
fi

# ---------------------------------------------------------------------------
# Build the /e2e command
# ---------------------------------------------------------------------------
CMD="/e2e ${PROFILE}"
if [[ -n "$LABEL_FILTER" ]]; then
    CMD="${CMD} --label-filter=\"${LABEL_FILTER}\""
fi

# ---------------------------------------------------------------------------
# Confirmation prompt
# ---------------------------------------------------------------------------
echo ""
echo "Triggering: ${CMD} on PR #${PR}"

if [[ -n "$ARG_PROFILE" && -n "$ARG_PR" && -n "$ARG_LABEL_FILTER" ]]; then
    # All flags provided non-interactively; skip confirmation.
    CONFIRMED=1
else
    printf "Continue? [Y/n] "
    read -r confirm
    if [[ -z "$confirm" || "$confirm" =~ ^[Yy]$ ]]; then
        CONFIRMED=1
    else
        CONFIRMED=0
    fi
fi

if [[ $CONFIRMED -ne 1 ]]; then
    echo "Aborted."
    exit 0
fi

# ---------------------------------------------------------------------------
# Post the comment
# ---------------------------------------------------------------------------
gh pr comment "$PR" --body "$CMD"

echo ""
echo "Triggered. Watch progress on PR #${PR}."
