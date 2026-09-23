#!/usr/bin/env bash
#
# Generic cherry-pick engine, split across two jobs so the write token never
# shares a runner with the conflict-resolution agent. Repos come from the caller.
#
#   pick    (Job A, READ token) clone, cherry-pick -x, leave conflicts for Claude.
#           Emits outcome=clean|conflict|empty|already.
#   export  (Job A, no token)   git format-patch the resolved tree (+ report) into
#           EXPORT_DIR. Emits export=ready|noop.
#   apply   (Job B, WRITE token, fresh runner) fresh-clone, git am the patch,
#           build the PR body/labels, push, open the PR.
#
# Common env: SOURCE_REPO TARGET_REPO TARGET_BRANCH PR_NUMBER MERGE_SHA
# pick/apply: TARGET_TOKEN (read for pick, write for apply), SOURCE_TOKEN
# export    : EXPORT_DIR OUTCOME CONFLICT_SEVERITY RESOLUTION_REPORT
# apply     : EXPORT_DIR EXTRA_LABELS TITLE_PREFIX OUTCOME CONFLICT_SEVERITY
# Optional  : SOURCE_REF(=master) BRANCH_NAME WORKDIR(=PWD) CARRY_SOURCE_LABELS(=true)
set -o errexit -o nounset -o pipefail

: "${SOURCE_REPO:?}" "${TARGET_REPO:?}" "${TARGET_BRANCH:?}"
: "${PR_NUMBER:?}" "${MERGE_SHA:?}"
SOURCE_REF="${SOURCE_REF:-master}"
EXTRA_LABELS="${EXTRA_LABELS:-}"
CARRY_SOURCE_LABELS="${CARRY_SOURCE_LABELS:-true}"
WORKDIR="${WORKDIR:-$PWD}"
EXPORT_DIR="${EXPORT_DIR:-/tmp/pick-export}"
TITLE_PREFIX="${TITLE_PREFIX-__DERIVE__}"

src_org="${SOURCE_REPO%%/*}"; src_name="${SOURCE_REPO##*/}"

# Deterministic branch (identical in both jobs), so re-runs are idempotent. No
# '#': it breaks the claude-code-action's internal git handling.
BRANCH_NAME="${BRANCH_NAME:-auto-pick-of-${src_name}-${PR_NUMBER}-${TARGET_BRANCH}}"
BRANCH_NAME="$(printf '%s' "$BRANCH_NAME" | sed 's/[^A-Za-z0-9._-]/-/g')"

mask() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::add-mask::$1" || true; }
emit() { echo "$1"; [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1" >>"$GITHUB_OUTPUT" || true; }

# ---------------------------------------------------------------------------
# Job A: pick
# ---------------------------------------------------------------------------
do_pick() {
  : "${TARGET_TOKEN:?}"
  local src_token="${SOURCE_TOKEN:-$TARGET_TOKEN}"
  mask "$TARGET_TOKEN"; mask "$src_token"
  local tgt_url="https://x-access-token:${TARGET_TOKEN}@github.com/${TARGET_REPO}.git"
  local src_url="https://x-access-token:${src_token}@github.com/${SOURCE_REPO}.git"

  cd "$WORKDIR"
  git config --global user.name  "oss-pick-bot"
  git config --global user.email "oss-pick-bot@users.noreply.github.com"
  emit "branch=$BRANCH_NAME"

  if ! git ls-remote "$tgt_url" HEAD >/dev/null 2>&1; then
    echo "::error::cannot reach ${TARGET_REPO} with the supplied token"; exit 1
  fi
  # Idempotency: a matching PR (any state) means the pick is already done. A
  # failed lookup must NOT read as "no PR". (Branch cleanup happens in Job B,
  # which has the write token.)
  local prnum
  if ! prnum="$(GH_TOKEN="$TARGET_TOKEN" gh pr list -R "$TARGET_REPO" --head "$BRANCH_NAME" --state all --json number --jq '.[0].number // empty')"; then
    echo "::error::cannot list PRs for ${BRANCH_NAME} on ${TARGET_REPO}"; exit 1
  fi
  if [ -n "$prnum" ]; then
    echo "Branch $BRANCH_NAME already has PR #${prnum} on ${TARGET_REPO}; already picked."
    emit "outcome=already"; return 0
  fi

  git clone "$tgt_url" .
  git remote add source "$src_url"
  git fetch --no-tags source "$SOURCE_REF"
  # Drop tokened URLs from .git/config before the agent sees the workspace.
  git remote set-url origin "https://github.com/${TARGET_REPO}.git"
  git remote set-url source "https://github.com/${SOURCE_REPO}.git"
  git checkout -b "$BRANCH_NAME" "origin/${TARGET_BRANCH}"

  # Squash/single-parent -> plain pick; true merge commit -> -m 1.
  local parents; parents="$(git show --no-patch --format='%P' "$MERGE_SHA" | wc -w)"
  local rc=0
  if [ "$parents" -ge 2 ]; then
    git cherry-pick -x -m 1 "$MERGE_SHA" || rc=$?
  else
    git cherry-pick -x "$MERGE_SHA" || rc=$?
  fi

  if [ "$rc" -eq 0 ]; then
    echo "Clean cherry-pick."; emit "outcome=clean"
  elif git diff --name-only --diff-filter=U | grep -q .; then
    echo "Conflicts:"; git diff --name-only --diff-filter=U; emit "outcome=conflict"
  else
    echo "Cherry-pick empty (already present / superseded)."
    git cherry-pick --abort || true; emit "outcome=empty"
  fi
}

# ---------------------------------------------------------------------------
# Job A: export (no token). Turn the resolved commit into a portable patch plus
# the report/severity/meta, so Job B can rebuild it on a clean runner.
# ---------------------------------------------------------------------------
do_export() {
  cd "$WORKDIR"
  # An unfinished cherry-pick or leftover markers is real breakage.
  if [ -e .git/CHERRY_PICK_HEAD ]; then
    echo "::error::cherry-pick still in progress; refusing to export"; exit 1
  fi
  # No NET change over the base means the OSS change was fully superseded once
  # resolved: a legitimate "nothing to pick", not an error.
  if git diff --quiet "origin/${TARGET_BRANCH}" HEAD 2>/dev/null; then
    echo "::notice::resolution produced no net change over origin/${TARGET_BRANCH}; nothing to pick"
    emit "export=noop"; return 0
  fi
  local f
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    if grep -qE '^(<<<<<<<|>>>>>>>)' "$f"; then
      echo "::error::conflict markers remain in $f; refusing to export"; exit 1
    fi
  done < <(git diff --name-only "origin/${TARGET_BRANCH}..HEAD")

  rm -rf "$EXPORT_DIR"; mkdir -p "$EXPORT_DIR/patches"
  git format-patch --no-signature -o "$EXPORT_DIR/patches" "origin/${TARGET_BRANCH}..HEAD" >/dev/null
  if ! ls "$EXPORT_DIR"/patches/*.patch >/dev/null 2>&1; then
    echo "::notice::no commits to export; nothing to pick"; emit "export=noop"; return 0
  fi
  # Carry the AI resolution report for Job B's PR body (treated as data).
  if [ -n "${RESOLUTION_REPORT:-}" ] && [ -s "$RESOLUTION_REPORT" ]; then
    cp "$RESOLUTION_REPORT" "$EXPORT_DIR/report.md"
  fi
  echo "exported $(ls "$EXPORT_DIR"/patches/*.patch | wc -l) patch(es) to $EXPORT_DIR"
  emit "export=ready"
}

# Pure-ish text: build the PR title, body, and labels from the source PR
# metadata. Mirrors build-pr-description so the merge-queue-bot can parse the
# body ("**Original Commit SHA**:"). Reads the report from the artifact.
build_pr_text() {
  local src_token="${SOURCE_TOKEN:-$TARGET_TOKEN}"
  local pj title body labels
  pj="$(GH_TOKEN="$src_token" gh pr view -R "$SOURCE_REPO" "$PR_NUMBER" --json title,body,labels)"
  title="$(jq -r '.title' <<<"$pj")"
  body="$(jq -r '.body // ""' <<<"$pj")"
  labels="$(jq -r '.labels[].name' <<<"$pj")"

  local stripped; stripped="$(printf '%s' "$title" | sed 's/^\[.*\] //')"
  if [ "$SOURCE_REPO" != "$TARGET_REPO" ]; then
    body="$(printf '%s' "$body" | sed "s/\([^a-zA-Z0-9_.-]\|^\)#\([0-9]\+\)/\1${src_org}\/${src_name}#\2/g")"
  fi
  local section
  for section in "Todos" "Reminder for the reviewer"; do
    body="$(printf '%s\n' "$body" | awk '/^## '"$section"'/{skip=1;next} /^#/&&skip{skip=0} !skip')"
  done

  local prefix
  if [ "$TITLE_PREFIX" = "__DERIVE__" ]; then
    local rel="${TARGET_BRANCH#release-}"; rel="${rel#calient-}"; prefix="[$rel] "
  else
    prefix="$TITLE_PREFIX"
  fi
  PR_TITLE_OUT="${prefix}${stripped}"

  local report="$EXPORT_DIR/report.md"
  local conflicts="No conflicts: the cherry-pick applied cleanly."
  if [ "${OUTCOME:-}" = "conflict" ]; then
    if [ -s "$report" ]; then
      conflicts="$(cat "$report")"
    else
      conflicts=":warning: Conflicts were auto-resolved during the cherry-pick, but the resolution report is missing. Review the diff carefully before merging."
    fi
  fi
  local conflicts_block
  if [ "${OUTCOME:-}" = "conflict" ]; then
    local sevnote
    case "${CONFLICT_SEVERITY:-}" in
      light) sevnote="**Conflict severity:** light (straightforward resolution)" ;;
      heavy) sevnote="**Conflict severity:** heavy (needed real judgement, please review closely)" ;;
      *)     sevnote="**Conflict severity:** unspecified" ;;
    esac
    conflicts_block="$(printf '## Conflicts resolved\n%s\n\n<details>\n<summary><b>AI conflict-resolution report</b> (click to expand)</summary>\n\n%s\n</details>' "$sevnote" "$conflicts")"
  else
    conflicts_block="$(printf '## Conflicts\n%s' "$conflicts")"
  fi

  PR_BODY_OUT="$(cat <<EOF
**Cherry-pick history**
- Pick onto **${TARGET_BRANCH}**: ${src_org}/${src_name}#${PR_NUMBER}

${conflicts_block}

## Original PR description
${body}

<details>
<summary><b>Automated Cherry-Pick PR details</b></summary>

This pull request was automatically created to synchronise the change below.

- **Original PR ID**: ${PR_NUMBER}
- **Original Commit SHA**: ${MERGE_SHA:0:10}
- **Source Repo**: \`${SOURCE_REPO}\`
- **Target Repo**: \`${TARGET_REPO}\`
- **Target Branch**: \`${TARGET_BRANCH}\`
</details>
EOF
)"

  local carried=""
  if [ "$CARRY_SOURCE_LABELS" = "true" ]; then
    carried="$(printf '%s\n' "$labels" | sort -u | grep '.' \
      | grep -vxE 'cherry-pick-candidate|skip-bot-cherry-pick' | paste -sd, || true)"
  fi
  PR_LABELS_OUT="$carried"
  if [ -n "$EXTRA_LABELS" ]; then
    PR_LABELS_OUT="${PR_LABELS_OUT:+$PR_LABELS_OUT,}$EXTRA_LABELS"
  fi
  if [ "${OUTCOME:-}" = "conflict" ]; then
    local clabel
    case "${CONFLICT_SEVERITY:-}" in
      light) clabel="auto-pick-conflict-light" ;;
      heavy) clabel="auto-pick-conflict-heavy" ;;
      *)     clabel="auto-pick-conflict" ;;
    esac
    PR_LABELS_OUT="${PR_LABELS_OUT:+$PR_LABELS_OUT,}$clabel"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Job B: apply (write token, fresh runner). Rebuild the resolved commit from the
# artifact patch on a clean clone, then push and open the PR.
# ---------------------------------------------------------------------------
do_apply() {
  : "${TARGET_TOKEN:?}"
  local src_token="${SOURCE_TOKEN:-$TARGET_TOKEN}"
  mask "$TARGET_TOKEN"; mask "$src_token"
  local tgt_url="https://x-access-token:${TARGET_TOKEN}@github.com/${TARGET_REPO}.git"
  export GH_TOKEN="$TARGET_TOKEN"

  if ! ls "$EXPORT_DIR"/patches/*.patch >/dev/null 2>&1; then
    echo "::error::no patch found in $EXPORT_DIR; nothing to apply"; exit 1
  fi

  cd "$WORKDIR"
  git config --global user.name  "oss-pick-bot"
  git config --global user.email "oss-pick-bot@users.noreply.github.com"

  # Idempotency + stranded-branch cleanup, now with the write token.
  local prnum
  if git ls-remote --exit-code --heads "$tgt_url" "$BRANCH_NAME" >/dev/null 2>&1; then
    if ! prnum="$(gh pr list -R "$TARGET_REPO" --head "$BRANCH_NAME" --state all --json number --jq '.[0].number // empty')"; then
      echo "::error::cannot list PRs for ${BRANCH_NAME} on ${TARGET_REPO}; refusing to touch the branch"; exit 1
    fi
    if [ -n "$prnum" ]; then
      echo "Branch $BRANCH_NAME already has PR #${prnum}; nothing to do."; emit "pr_url="; return 0
    fi
    echo "::warning::Branch $BRANCH_NAME exists with no PR (stranded); deleting."
    git push "$tgt_url" --delete "$BRANCH_NAME" || true
  fi

  git clone "$tgt_url" .
  git checkout -b "$BRANCH_NAME" "origin/${TARGET_BRANCH}"
  # Apply the resolved commit. If the base moved and it no longer applies, fail
  # loudly rather than pushing a broken tree.
  if ! git am "$EXPORT_DIR"/patches/*.patch; then
    git am --abort || true
    echo "::error::patch no longer applies onto origin/${TARGET_BRANCH} (base moved?); re-run the pick"; exit 1
  fi

  build_pr_text

  git push "$tgt_url" "HEAD:${BRANCH_NAME}"

  local IFS=','; local l
  for l in $PR_LABELS_OUT; do
    [ -n "$l" ] && gh label create "$l" -R "$TARGET_REPO" >/dev/null 2>&1 || true
  done
  unset IFS

  local body_file; body_file="$(mktemp)"
  printf '%s\n' "$PR_BODY_OUT" >"$body_file"

  local pr_url
  pr_url="$(gh pr create \
    --repo "$TARGET_REPO" \
    --base "$TARGET_BRANCH" \
    --head "$BRANCH_NAME" \
    --title "$PR_TITLE_OUT" \
    --body-file "$body_file" \
    ${PR_LABELS_OUT:+--label "$PR_LABELS_OUT"})"
  echo "$pr_url"
  emit "pr_url=$pr_url"
}

case "${1:-}" in
  pick)   do_pick ;;
  export) do_export ;;
  apply)  do_apply ;;
  *) echo "usage: $0 {pick|export|apply}" >&2; exit 2 ;;
esac
