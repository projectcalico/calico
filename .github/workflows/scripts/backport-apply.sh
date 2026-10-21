#!/usr/bin/env bash
#
# Job B of the test-fix backport: verify Job A's patches, then push and open PRs.
# No agent ever runs here.
set -o errexit -o nounset -o pipefail

SCRIPTS_DIR="${SCRIPTS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
# shellcheck source=backport-lib.sh
source "$SCRIPTS_DIR/backport-lib.sh"

REPO="${REPO:-}"
WORKDIR="${WORKDIR:-$PWD}"
IN_DIR="${IN_DIR:-/tmp/backport-out}"
DRY_RUN="${DRY_RUN:-true}"
SINCE_DAYS="${SINCE_DAYS:-14}"
AS_OF="${AS_OF:-}"
BOT_NAME="${BOT_NAME:-Marvin Robot}"
BOT_EMAIL="${BOT_EMAIL:-marvin@tigera.io}"
MAX_EXTRA_LINES="${MAX_EXTRA_LINES:-40}"

mask() { [ -z "${GITHUB_ACTIONS:-}" ] || echo "::add-mask::$1"; }
summary() { if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat >>"$GITHUB_STEP_SUMMARY"; else cat; fi; }
oneline() { tr '\t\n\r<>`|' '      ' | sed 's/ *$//' | cut -c1-"${1:-200}"; }

window_until() {
  if [ -n "$AS_OF" ]; then date -u -d "${AS_OF} 23:59:59" +%s; else date -u +%s; fi
}

ref_at() { git rev-list -1 --first-parent --before="@$2" "$1"; }

# Changed lines the master commit lacks, for every commit in RANGE; empty means verbatim.
# Prints "<pick sha>\t<path>\t<+|->\t<text>".
extras_for_range() {
  local c m
  for c in $(git rev-list --reverse "$1"); do
    m="$(master_of "$c")"
    backport_extra_lines "$c" "$m" | sed "s/^/${c}\t/"
  done
}

# The master commit a pick names in its last "(cherry picked from commit ...)" line.
master_of() {
  git log -1 --format=%B "$1" | sed -nE 's/^\(cherry picked from commit ([0-9a-f]{40})\)$/\1/p' | tail -1
}

# Accepts RANGE only if each commit is a test-only pick of a distinct master PR in the window.
verify_range() {
  local range="$1" window="$2" c m pr seen=" "
  for c in $(git rev-list --reverse "$range"); do
    m="$(master_of "$c")"
    [ -n "$m" ] || { echo "commit ${c:0:12} names no master commit"; return 1; }
    pr="$(awk -F'\t' -v s="$m" '$1 == s { print $2 }' "$window")"
    [ -n "$pr" ] || { echo "commit ${c:0:12} picks ${m:0:12}, which is not a master merge in the window"; return 1; }
    case "$seen" in *" $m "*) echo "master commit ${m:0:12} is picked twice"; return 1 ;; esac
    seen="${seen}${m} "
    git diff --name-only "${m}^1" "$m" | backport_all_test_paths ||
      { echo "master PR #${pr} changes non-test files"; return 1; }
    git diff --name-only "${c}^1" "$c" | backport_all_test_paths ||
      { echo "the pick of #${pr} changes non-test files"; return 1; }
  done
}

# Files master commit M changes that pick C leaves out.
left_out() {
  git diff --name-only "${1}^1" "$1" >"$LEFT_OUT_TMP"
  git diff --name-only "${2}^1" "$2" | grep -vxF -f "$LEFT_OUT_TMP" || true
}

# Title of master commit SHA: a squash subject without "(#N)", or a merge commit's PR title line.
master_title() {
  if [ "$(git show --no-patch --format=%P "$1" | wc -w)" -ge 2 ]; then
    git log -1 --format=%b "$1" | grep -m1 . | oneline 120
  else
    git log -1 --format=%s "$1" | sed -E 's/ \(#[0-9]+\)$//' | oneline 120
  fi
}

build_body() {
  local branch="$1" release="$2" window="$3" extras="$4" c m pr title res n out
  local left; left="$(mktemp)"
  echo "Automated batch backport of test fixes from \`master\` to \`${branch}\`."
  echo
  echo "| Master PR | Change | Pick |"
  echo "|---|---|---|"
  for c in $(git rev-list --reverse "${release}..HEAD"); do
    m="$(master_of "$c")"
    pr="$(awk -F'\t' -v s="$m" '$1 == s { print $2 }' "$window")"
    [ -n "$pr" ] || pr="$(backport_pr_of "$(git log -1 --format=%s "$c")")"
    title="$(master_title "$m")"
    if grep -q "^${c}"$'\t' "$extras"; then res=":warning: conflict resolved by AI, see *Needs review*"; else res="verbatim"; fi
    out="$(left_out "$c" "$m")"
    if [ -n "$out" ]; then
      res="${res}, $(wc -l <<<"$out") file(s) left out"
      { echo "- #${pr}:"; awk '{ print "  - `" $0 "`" }' <<<"$out"; } >>"$left"
    fi
    echo "| #${pr} | ${title} | ${res} |"
  done
  if [ -s "$left" ]; then
    echo
    echo "### Left out"
    echo "Files the master change touches that are not on this branch:"
    cat "$left"
  fi
  if [ -s "$extras" ]; then
    echo
    echo "### Needs review"
    echo "Changed lines that the master commit does not have, written by the AI conflict resolution:"
    for c in $(cut -f1 "$extras" | uniq); do
      m="$(master_of "$c")"
      pr="$(awk -F'\t' -v s="$m" '$1 == s { print $2 }' "$window")"
      n="$(grep -c "^${c}"$'\t' "$extras")"
      echo
      echo "<details><summary>#${pr:-?}: ${n} line(s)</summary>"
      echo
      echo '```diff'
      grep "^${c}"$'\t' "$extras" | head -n "$MAX_EXTRA_LINES" |
        awk -F'\t' '{ t = $4; gsub(/```/, "` ` `", t); print $3 t "    # " $2 }'
      [ "$n" -le "$MAX_EXTRA_LINES" ] || echo "# ... $((n - MAX_EXTRA_LINES)) more"
      echo '```'
      if [ -s "$IN_DIR/reports/${branch}-${pr}.md" ]; then
        echo
        echo "AI resolution report (unverified):"
        echo
        echo '```text'
        # shellcheck disable=SC2016 # literal backticks
        head -c 3000 "$IN_DIR/reports/${branch}-${pr}.md" | sed 's/```/` ` `/g'
        echo
        echo '```'
      fi
      echo "</details>"
    done
  fi
  jq -r --arg b "$branch" '
    [.branches[] | select(.branch == $b) | .skipped[]
     | select(.reason | test("^(target_missing|needs_prereq|resolve_failed|compile_fail|deferred)$"))] as $s
    | if ($s | length) > 0 then
        "\n### Not picked", ($s[] | "- #\(.pr | tonumber): \(.reason)")
      else empty end' "$IN_DIR/report.json"
  cat <<'EOF'

**Release note:**
```release-note
None
```

**AI assistance:** Claude chose these test fixes from their PR descriptions and resolved the conflicts marked above. Each pick is checked against its master commit; lines that differ are listed under *Needs review*.
EOF
}

ensure_label() {
  gh api "repos/${REPO}/labels" -f name="$BACKPORT_LABEL" -f color=ededed \
    -f description="Automated batch backport of test fixes" >/dev/null 2>&1 || true
}

# marvin-tigera may race the first label write on a new PR, so write the set again once.
set_labels() {
  local pr="$1" f
  f="$(mktemp)"
  echo "{\"labels\":[\"docs-not-required\",\"release-note-not-required\",\"${BACKPORT_LABEL}\"]}" >"$f"
  gh api "repos/${REPO}/issues/${pr}/labels" --method PUT --input "$f" >/dev/null
  sleep 60
  grep -qx release-note-not-required <<<"$(gh api "repos/${REPO}/issues/${pr}/labels" --jq '.[].name')" ||
    gh api "repos/${REPO}/issues/${pr}/labels" --method PUT --input "$f" >/dev/null
}

apply_branch() {
  local branch="$1" window="$2" release head mbox reason extras body_file open
  mbox="$IN_DIR/${branch}.mbox"
  [ -s "$mbox" ] || { echo "- ${branch}: no picks" | summary; return 0; }

  release="$(git rev-parse "origin/${branch}")"
  if [ -n "$AS_OF" ]; then
    release="$(ref_at "origin/${branch}" "$(window_until)")"
  else
    open="$(backport_open_batch "$REPO" "$branch")"
    if [ -n "$open" ]; then
      echo "- ${branch}: held, batch PR #$(cut -f1 <<<"$open") is open" | summary; return 0
    fi
  fi
  if [ "$(jq -r --arg b "$branch" '.branches[] | select(.branch == $b) | .base_sha' "$IN_DIR/report.json")" != "$release" ]; then
    echo "- ${branch}: rejected, the picks were made on another base" | summary; return 0
  fi

  git checkout -q -B "verify-${branch}" "$release"
  if ! git am -q -k "$mbox" >/dev/null 2>&1; then
    git am --abort >/dev/null 2>&1 || true
    echo "- ${branch}: rejected, the patches do not apply" | summary; return 0
  fi
  if ! reason="$(verify_range "${release}..HEAD" "$window")"; then
    echo "- ${branch}: rejected, ${reason}" | summary; return 0
  fi
  extras="$(mktemp)"
  extras_for_range "${release}..HEAD" >"$extras"
  body_file="$(mktemp)"
  build_body "$branch" "$release" "$window" "$extras" >"$body_file"

  local title
  title="[$(backport_short "$branch")] Backport test fixes $(date -u +%Y-%m-%d)"
  if [ "$DRY_RUN" = true ]; then
    { echo "- ${branch}: dry run, would open $(git rev-list --count "${release}..HEAD") pick(s)"
      echo; echo "<details><summary>${title}</summary>"; echo; cat "$body_file"; echo "</details>"; echo; } | summary
    return 0
  fi

  head="${BACKPORT_BRANCH_PREFIX}$(backport_short "$branch")-$(date -u +%Y%m%d)"
  if git ls-remote --exit-code --heads "$PUSH_URL" "$head" >/dev/null 2>&1; then
    head="${head}-${GITHUB_RUN_ID:-$$}"
  fi
  git push -q "$PUSH_URL" "HEAD:refs/heads/${head}"
  ensure_label
  local pr
  pr="$(gh api "repos/${REPO}/pulls" -f title="$title" -f head="$head" -f base="$branch" \
    -F body=@"$body_file" --jq .number)"
  set_labels "$pr"
  echo "- ${branch}: opened #${pr}" | summary
}

main() {
  : "${REPO:?}" "${TARGET_TOKEN:?}"
  mask "$TARGET_TOKEN"
  export GH_TOKEN="$TARGET_TOKEN"
  PUSH_URL="https://x-access-token:${TARGET_TOKEN}@github.com/${REPO}.git"
  LEFT_OUT_TMP="$(mktemp)"
  [ -s "$IN_DIR/report.json" ] || { echo "::error::no report.json in $IN_DIR"; exit 1; }
  [ -z "$AS_OF" ] || DRY_RUN=true

  git clone -q --no-tags "$PUSH_URL" "$WORKDIR"
  cd "$WORKDIR"
  git remote set-url origin "https://github.com/${REPO}.git"
  git config user.name "$BOT_NAME"
  git config user.email "$BOT_EMAIL"

  local until since master window
  until="$(window_until)"
  since=$((until - SINCE_DAYS * 86400))
  master="$(ref_at origin/master "$until")"
  window="$(mktemp)"
  backport_master_window "$master" "$since" "$until" >"$window"

  echo "### Test-fix backport: PRs (dry run: ${DRY_RUN})" | summary
  local branch
  while IFS= read -r branch; do
    apply_branch "$branch" "$window"
  done < <(git for-each-ref --format='%(refname:lstrip=3)' refs/remotes/origin/ | backport_targets)
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
