#!/usr/bin/env bash

# Tests the test-fix backport scripts on a throwaway git repo, without network or Claude.
# Run with:  bash .github/workflows/scripts/backport-test-fixes_test.sh

set -o errexit -o nounset -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=backport-lib.sh
source "${SCRIPT_DIR}/backport-lib.sh"

PASS=0
FAIL=0

check() {
  local name="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL: ${name}"
    echo "  expected: $(printf '%q' "$expected")"
    echo "  actual:   $(printf '%q' "$actual")"
  fi
}

###############################################################################
# Pure helpers
###############################################################################

check "OSS targets" "$(printf '%s\n' release-v3.30 release-v3.31 release-v3.33 release-v3.32 release-v3.33-foo master |
  backport_targets | paste -sd' ')" "release-v3.33 release-v3.32 release-v3.31"

check "EE targets, GA branch cut" "$(printf '%s\n' release-calient-v3.21 release-calient-v3.22 release-calient-v3.23 \
  release-calient-v3.24 release-calient-v3.24-1 release-calient-v3.24-2 release-calient-v3.22.2-hotfix \
  release-calient-v3.23.1-cloud | backport_targets | paste -sd' ')" \
  "release-calient-v3.24 release-calient-v3.23 release-calient-v3.22"

check "EE targets, pre-release only" "$(printf '%s\n' release-calient-v3.22 release-calient-v3.23 \
  release-calient-v3.24 release-calient-v3.25-1 release-calient-v3.25-2 | backport_targets | paste -sd' ')" \
  "release-calient-v3.25-2 release-calient-v3.24 release-calient-v3.23 release-calient-v3.22"

for p in felix/fv/a.txt felix/bpf/ut/x.go felix/bpf-gpl/ut/y.c e2e/pkg/z.go hack/test/t.sh \
  process/testing/aso/vmss.sh libcalico-go/lib/testutils/u.go felix/config/testdata/d.yaml lib/x_test.go; do
  check "test path ${p}" "$(backport_is_test_path "$p" && echo yes || echo no)" yes
done
for p in felix/dataplane/linux/x.go .semaphore/semaphore.yml .github/workflows/x_test.go felix/fvx/y.go \
  felix/testing.go deps.txt; do
  check "product path ${p}" "$(backport_is_test_path "$p" && echo yes || echo no)" no
done
check "all test paths, empty" "$(printf '' | backport_all_test_paths && echo yes || echo no)" no
check "all test paths, mixed" "$(printf 'a/fv/x.go\nb/y.go\n' | backport_all_test_paths && echo yes || echo no)" no

check "PR of a merge" "$(backport_pr_of 'Merge pull request #14139 from tomastigera/bp')" 14139
check "PR of a squash" "$(backport_pr_of 'winfv: ride through the race (#14077) (#14044)')" 14044
check "PR of a direct push" "$(backport_pr_of 'Fix things')" ""
check "short OSS" "$(backport_short release-v3.33)" v3.33
check "short EE pre-release" "$(backport_short release-calient-v3.24-1)" v3.24-1

check "diff lines keep -- content" "$(printf '%s\n' 'diff --git a/f b/f' '--- a/f' '+++ b/f' '@@ -1,2 +1,2 @@' \
  ' ctx' '--- removed dashes' '+++ added pluses' | backport_diff_lines | paste -sd'|')" \
  "f	-	-- removed dashes|f	+	++ added pluses"

###############################################################################
# Fixture repo
###############################################################################

TMP="$(mktemp -d)"
trap '[ -n "${KEEP_TMP:-}" ] || rm -rf "$TMP"' EXIT
export GIT_AUTHOR_NAME=dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=dev GIT_COMMITTER_EMAIL=dev@example.com
export GIT_CONFIG_GLOBAL="$TMP/gitconfig" GIT_CONFIG_NOSYSTEM=1
git config --global init.defaultBranch master
git config --global advice.detachedHead false

SRC="$TMP/src"
git init -q "$SRC"
cd "$SRC"
mkdir -p felix/fv e2e
printf 'l1\nl2\nl3\nl4\nl5\n' >felix/fv/a.txt
echo b1 >felix/fv/b.txt
echo product >felix/x.go
mkdir -p pkg/fv
printf 'module example.com/fx\n\ngo 1.22\n' >go.mod
printf 'package fv\n' >pkg/fv/base_test.go
git add -A && git commit -qm "base"
for b in release-v3.30 release-v3.31 release-v3.32 release-v3.33; do git branch "$b"; done
git checkout -q release-v3.32 && sed -i 's/^l4$/l4-v332/' felix/fv/a.txt && git commit -qam "v3.32 local change"
git checkout -q master

squash() { git add -A && git commit -qm "$1"; }
merge_pr() {
  local n="$1" title="$2"
  git checkout -q -b "pr$n"
  "${@:3}"
  git add -A && git commit -qm "$title"
  git checkout -q master
  git merge -q --no-ff "pr$n" -m "Merge pull request #$n from dev/pr$n" -m "$title"
}

echo c1 >e2e/c.txt && squash "Add c test (#10)"
merge_pr 11 "Fix a flake in a_test" sed -i 's/^l2$/l2-fixed/' felix/fv/a.txt
merge_pr 12 "Fix c test" sed -i 's/^c1$/c1-fixed/' e2e/c.txt
echo changed >felix/x.go && squash "Product fix (#13)"
sed -i 's/^l4$/l4-fixed/' felix/fv/a.txt && squash "Fix l4 flake (#14)"
echo b2 >>felix/fv/b.txt && squash "Fix b flake (#15)"
SHA15="$(git rev-parse HEAD)"
echo b3 >>felix/fv/b.txt && echo c2 >>e2e/c.txt && squash "Fix b and c (#18)"
printf 'package fv\n\nfunc helper() int { return 1 }\n' >pkg/fv/helper_test.go && squash "Add a test helper (#16)"
printf 'package fv\n\nvar _ = helper()\n' >pkg/fv/use_test.go && squash "Use the helper (#17)"
git checkout -q release-v3.33 && git cherry-pick -x "$SHA15" >/dev/null &&
  git commit -q --amend -m "Fix b flake (#15)" && git checkout -q master

# The scripts see the fixture through a clone, as in CI.
WORK="$TMP/work"
git clone -q --no-tags "$SRC" "$WORK"
mkdir -p "$TMP/bin"
printf '#!/bin/sh\nexit 0\n' >"$TMP/bin/gh" && chmod +x "$TMP/bin/gh"

STATE="$TMP/state"
OUT="$TMP/out"
run_pick() {
  PATH="$TMP/bin:$PATH" REPO=example/calico WORKDIR="$WORK" STATE_DIR="$STATE" OUT_DIR="$OUT" \
    SCRIPTS_DIR="$SCRIPT_DIR" PRS="11,12,13,14,15,17,18" MAX_RESOLVES=0 GOTOOLCHAIN=local \
    bash "$SCRIPT_DIR/backport-pick.sh" "$@" >/dev/null
}

run_pick select
check "targets" "$(cut -f1 "$STATE/targets.tsv" | paste -sd'|')" "release-v3.33|release-v3.32|release-v3.31"
check "candidates" "$(cut -f2,3 "$STATE/candidates.tsv" | paste -sd'|')" \
  "11	release-v3.33,release-v3.32,release-v3.31|12	release-v3.33,release-v3.32,release-v3.31|14	release-v3.33,release-v3.32,release-v3.31|15	release-v3.32,release-v3.31|18	release-v3.33,release-v3.32,release-v3.31|17	release-v3.33,release-v3.32,release-v3.31"
check "counts" "$(cat "$STATE/counts.tsv")" "1	0"

# Stand-in for classify: every candidate qualifies.
cp "$STATE/candidates.tsv" "$STATE/qualified.tsv"
printf '11\tFix a flake in a_test\n12\tFix c test\n' >"$STATE/titles.tsv"
: >"$STATE/not-qualified.tsv"
run_pick pick

results() { awk -F'\t' -v b="$1" '$1 == b { print $2 ":" $4 }' "$STATE/results.tsv" | paste -sd' '; }
check "v3.33 results" "$(results release-v3.33)" "11:picked_clean 12:target_missing 14:picked_clean 18:deferred 17:compile_fail"
check "v3.32 results" "$(results release-v3.32)" "11:picked_clean 12:target_missing 14:deferred 15:picked_clean 18:deferred 17:compile_fail"
check "v3.31 results" "$(results release-v3.31)" "11:picked_clean 12:target_missing 14:picked_clean 15:picked_clean 18:deferred 17:compile_fail"
check "report picks" "$(jq -c '[.branches[] | {(.branch): [.picked[].pr]}] | add' "$OUT/report.json")" \
  '{"release-v3.33":[11,14],"release-v3.32":[11,15],"release-v3.31":[11,14,15]}'
check "merge pick message" "$(grep -m1 '^Subject:' "$OUT/release-v3.31.mbox")" "Subject: Fix a flake in a_test (#11)"

###############################################################################
# Job B checks
###############################################################################

# shellcheck source=backport-apply.sh
source "$SCRIPT_DIR/backport-apply.sh"
cd "$WORK"
git config user.name dev && git config user.email dev@example.com
WINDOW="$TMP/window"
backport_master_window origin/master "$(( $(date -u +%s) - 86400 ))" "$(date -u +%s)" >"$WINDOW"

git checkout -q -B verify origin/release-v3.31
git am -q -k "$OUT/release-v3.31.mbox"
check "verify clean picks" "$(verify_range origin/release-v3.31..HEAD "$WINDOW" && echo ok)" ok
check "clean picks are verbatim" "$(extras_for_range origin/release-v3.31..HEAD)" ""

# A resolution that adds a line master never had.
git checkout -q -B verify origin/release-v3.31
git am -q -k "$OUT/release-v3.31.mbox"
echo "sneaky" >>felix/fv/a.txt && git commit -q --amend --no-edit -a
check "extra line is flagged" "$(extras_for_range HEAD~1..HEAD | cut -f2-)" "felix/fv/a.txt	+	sneaky"

# A pick that touches product code is rejected.
echo evil >>felix/x.go && git commit -q --amend --no-edit -a
check "product path rejected" "$(verify_range HEAD~1..HEAD "$WINDOW" || true)" "the pick of #15 changes non-test files"

# A pick that names a commit outside the window is rejected.
git checkout -q -B verify origin/release-v3.31
echo x >>felix/fv/a.txt && git commit -qam "Not a pick"$'\n\n'"(cherry picked from commit $(printf 'a%.0s' {1..40}))"
check "unknown master commit rejected" "$(verify_range HEAD~1..HEAD "$WINDOW" || true)" \
  "commit $(git rev-parse --short=12 HEAD) picks aaaaaaaaaaaa, which is not a master merge in the window"

echo
echo "passed: ${PASS}, failed: ${FAIL}"
[ "$FAIL" -eq 0 ]
