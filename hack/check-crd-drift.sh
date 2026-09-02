#!/bin/bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# check-crd-drift.sh: catches CRD and manifest drift that check-dirty cannot see.
# check-dirty proves the tree is self-consistent, never that regeneration still
# produces what master ships.
#
# Usage: hack/check-crd-drift.sh <manifests|orphans|sources|all>

set -e
set -u
set -o pipefail

cd "$(dirname "$0")/.."

# Generated CRD directories, each with the make target that fills it. Every glob
# is scoped to *.yaml because these directories also hold an embed.go.
CRD_DIRS=(
  "api/config/crd:api:gen-files"
  "libcalico-go/config/crd:libcalico-go:gen-crds"
  "operator/pkg/crds/operator:operator:manifests"
  "kube-controllers/pkg/apis/migration/v1/crd:kube-controllers:gen-files"
)

# Generic JSON schema keywords, dropped from check 1's results. Their removal
# never means a CRD field went missing, and they churn on every doc edit.
IGNORED_KEYS="description|allOf|anyOf|oneOf"

# Commit trailer that waives check 1, taking a comma-separated list of key names
# or the word "all".
REMOVAL_TRAILER="Allow-manifest-removals:"

# How many removed keys to name before summarizing the rest.
MAX_KEYS_SHOWN=25

###############################################################################
# Check 1: manifests diff against the merge base.
###############################################################################

# Resolves the ref to compare manifests/ against, printing nothing when there is
# no base to compare with.
resolve_base_ref() {
  if [ -n "${CRD_DRIFT_BASE_REF:-}" ]; then
    echo "${CRD_DRIFT_BASE_REF}"
    return
  fi
  # On a Semaphore pull request build, SEMAPHORE_GIT_BRANCH is the base branch.
  if [ -n "${SEMAPHORE_GIT_PR_NUMBER:-}" ] && [ -n "${SEMAPHORE_GIT_BRANCH:-}" ]; then
    if git fetch -q --no-tags origin "${SEMAPHORE_GIT_BRANCH}" 2>/dev/null; then
      echo FETCH_HEAD
    fi
    return
  fi
  if git rev-parse --verify -q origin/master >/dev/null; then
    echo origin/master
  fi
}

# Prints the mapping-key names that a diff removes without adding back anywhere.
removed_keys() {
  local diff=$1 removed added
  removed=$(printf '%s\n' "$diff" | grep -E '^-[[:space:]]*[A-Za-z_][A-Za-z0-9_.-]*:[[:space:]]*$' |
    sed -E 's/^-[[:space:]]*//; s/:[[:space:]]*$//' | sort -u || true)
  added=$(printf '%s\n' "$diff" | grep -E '^\+[[:space:]]*[A-Za-z_][A-Za-z0-9_.-]*:[[:space:]]*$' |
    sed -E 's/^\+[[:space:]]*//; s/:[[:space:]]*$//' | sort -u || true)
  comm -23 <(printf '%s\n' "$removed") <(printf '%s\n' "$added") |
    grep -vE "^(${IGNORED_KEYS})$" | grep -v '^$' || true
}

# Prints the keys waived by an Allow-manifest-removals trailer in the range.
waived_keys() {
  local range=$1
  git log --format=%B "$range" | grep -i "^${REMOVAL_TRAILER}" |
    sed -E "s/^[^:]*:[[:space:]]*//" | tr ',' '\n' | sed -E 's/[[:space:]]//g' | grep -v '^$' | sort -u || true
}

check_manifests() {
  local ref base range diff gone waived unwaived
  ref=$(resolve_base_ref)
  if [ -z "$ref" ]; then
    echo "No base ref available, skipping the manifests drift check."
    echo "Set CRD_DRIFT_BASE_REF to run it outside a pull request build."
    return 0
  fi
  base=$(git merge-base "$ref" HEAD)
  range="${base}..HEAD"
  echo "Comparing manifests/ against ${ref} (merge base ${base})"

  diff=$(git diff "$base" HEAD -- manifests/ | grep -v '^[-+]# Source:' || true)
  if [ -z "$diff" ]; then
    echo "No manifest changes."
    return 0
  fi
  git diff --stat "$base" HEAD -- manifests/

  gone=$(removed_keys "$diff")
  if [ -z "$gone" ]; then
    echo "No shipped manifest keys removed."
    return 0
  fi

  waived=$(waived_keys "$range")
  if printf '%s\n' "$waived" | grep -qix all; then
    echo "$(printf '%s\n' "$gone" | wc -l) manifest key removal(s) waived by an ${REMOVAL_TRAILER} trailer."
    return 0
  fi
  unwaived=$(comm -23 <(printf '%s\n' "$gone") <(printf '%s\n' "$waived") | grep -v '^$' || true)
  if [ -z "$unwaived" ]; then
    echo "$(printf '%s\n' "$gone" | wc -l) manifest key removal(s) waived by an ${REMOVAL_TRAILER} trailer."
    return 0
  fi

  local count trailer
  count=$(printf '%s\n' "$unwaived" | wc -l)
  if [ "$count" -gt "$MAX_KEYS_SHOWN" ]; then
    trailer="all"
  else
    trailer=$(printf '%s' "$unwaived" | paste -sd, -)
  fi

  cat <<EOF

${count} key(s) are in the shipped manifests on ${ref} and gone at HEAD:

$(printf '%s\n' "$unwaived" | head -n "$MAX_KEYS_SHOWN" | sed 's/^/  /')
$([ "$count" -gt "$MAX_KEYS_SHOWN" ] && echo "  ... and $((count - MAX_KEYS_SHOWN)) more")

A field that disappears from a shipped CRD breaks anyone whose resources set it,
and check-dirty cannot see it because the regenerated tree is self-consistent.
Regenerate and re-check, or record the removal as intentional with a commit
trailer:

  ${REMOVAL_TRAILER} ${trailer}

EOF
  return 1
}

###############################################################################
# Check 2: delete-and-regenerate orphan test.
###############################################################################

restore_crd_dirs() {
  local entry dir
  git checkout -- . || true
  for entry in "${CRD_DIRS[@]}"; do
    dir=${entry%%:*}
    git clean -fdq "$dir" || true
  done
}

check_orphans() {
  local entry dir component target before after missing failed=0
  # Untracked files are left alone; tracked ones all get restored on the way out.
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "ERROR: the orphan check rewrites generated files, so it needs a clean tree." >&2
    git status --porcelain --untracked-files=no >&2
    return 1
  fi
  trap restore_crd_dirs EXIT

  for entry in "${CRD_DIRS[@]}"; do
    IFS=: read -r dir component target <<<"$entry"
    echo "--- ${dir} (make -C ${component} ${target})"
    before=$(find "$dir" -maxdepth 1 -name '*.yaml' -printf '%f\n' | sort)
    rm -f "${dir}"/*.yaml
    make -C "$component" "$target"
    after=$(find "$dir" -maxdepth 1 -name '*.yaml' -printf '%f\n' | sort)
    missing=$(comm -23 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | grep -v '^$' || true)
    if [ -n "$missing" ]; then
      echo "ERROR: ${dir} shipped these CRDs but the generator no longer produces them:" >&2
      printf '  %s\n' $missing >&2
      failed=1
    fi
    restore_crd_dirs
  done

  if [ "$failed" != 0 ]; then
    cat >&2 <<'EOF'

An orphaned CRD is one whose Go type stopped being generated while the YAML
stayed behind. Delete the YAML if the API is gone, or restore the type.
EOF
    return 1
  fi
  echo "Every shipped CRD came back from its generator."
}

###############################################################################
# Check 3: copy/link audit.
###############################################################################

check_sources() {
  local link name file dir found failed=0
  while read -r link; do
    [ -n "$link" ] || continue
    if [ ! -e "$link" ]; then
      echo "ERROR: ${link} points at $(readlink "$link"), which does not exist." >&2
      failed=1
    fi
  done < <(find charts -type l)

  while read -r name; do
    [ -n "$name" ] || continue
    if [ ! -f "operator/pkg/crds/operator/${name}" ]; then
      echo "ERROR: calico_operator_crds.txt lists ${name}, which is not generated." >&2
      failed=1
    fi
  done < <(grep -vE '^[[:space:]]*(#|$)' operator/pkg/crds/calico_operator_crds.txt)

  # A copied CRD outlives its generator silently: nothing regenerates into a
  # chart, so the orphan check above cannot see it.
  while read -r file; do
    [ -n "$file" ] || continue
    found=false
    for dir in "${CRD_DIRS[@]}"; do
      if [ -f "${dir%%:*}/$(basename "$file")" ]; then
        found=true
        break
      fi
    done
    if [ "$found" != true ]; then
      echo "ERROR: ${file} is a copy of a CRD that no generator produces." >&2
      failed=1
    fi
  done < <(find charts -type f -name '*.*_*.yaml')

  if [ "$failed" != 0 ]; then
    return 1
  fi
  echo "Every chart CRD link and manifest list entry resolves to a generated file."
}

###############################################################################

case "${1:-}" in
manifests) check_manifests ;;
orphans) check_orphans ;;
sources) check_sources ;;
all)
  check_sources
  check_manifests
  check_orphans
  ;;
*)
  echo "Usage: $0 <manifests|orphans|sources|all>" >&2
  exit 1
  ;;
esac
