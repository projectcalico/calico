#!/usr/bin/env bash
#
# Generic cherry-pick engine for CI. Picks a merged PR's commit from
# SOURCE_REPO@SOURCE_REF onto TARGET_REPO@TARGET_BRANCH and opens a PR into the
# target. Hardcodes no repos: the calling workflow supplies the flow (one
# source/target per invocation), so the same script serves:
#   - OSS master  -> EE master        (cross-repo pick)
#   - OSS master  -> OSS release-vX.Y (same-repo backport)
#   - EE  master  -> EE  release-...  (same-repo backport)
#
# Two subcommands, because a Claude conflict-resolution step runs between them:
#   pick     clone target, cherry-pick (-x) the commit; leave conflicts in the
#            tree for Claude. Emits outcome=clean|conflict|empty|already.
#   open-pr  build the PR body/labels (bot-parseable meta block, label
#            carry-over, cross-repo #ref rewrite), push the branch, open the PR.
#
# Required env: SOURCE_REPO TARGET_REPO TARGET_BRANCH PR_NUMBER MERGE_SHA
#               TARGET_TOKEN
# Optional env: SOURCE_REF(=master) SOURCE_TOKEN(=TARGET_TOKEN) EXTRA_LABELS
#               CARRY_SOURCE_LABELS(=true) OUTCOME RESOLUTION_REPORT
#               CONFLICT_SEVERITY(light|heavy) BRANCH_NAME WORKDIR(=PWD)
set -o errexit -o nounset -o pipefail

: "${SOURCE_REPO:?}" "${TARGET_REPO:?}" "${TARGET_BRANCH:?}"
: "${PR_NUMBER:?}" "${MERGE_SHA:?}" "${TARGET_TOKEN:?}"
SOURCE_REF="${SOURCE_REF:-master}"
SOURCE_TOKEN="${SOURCE_TOKEN:-$TARGET_TOKEN}"
EXTRA_LABELS="${EXTRA_LABELS:-}"
CARRY_SOURCE_LABELS="${CARRY_SOURCE_LABELS:-true}"
WORKDIR="${WORKDIR:-$PWD}"
# Title prefix: if unset, derive "[<target-short>] " from the target branch
# (release-calient-v3.17 -> [v3.17]). A flow can override it (e.g. "[OSS pick] ",
# or "" for none).
TITLE_PREFIX="${TITLE_PREFIX-__DERIVE__}"

src_url="https://x-access-token:${SOURCE_TOKEN}@github.com/${SOURCE_REPO}.git"
tgt_url="https://x-access-token:${TARGET_TOKEN}@github.com/${TARGET_REPO}.git"
src_org="${SOURCE_REPO%%/*}"; src_name="${SOURCE_REPO##*/}"

# Deterministic branch, so re-runs are idempotent. No '#': it breaks the
# claude-code-action's internal git handling (it resets the workspace).
BRANCH_NAME="${BRANCH_NAME:-auto-pick-of-${src_name}-${PR_NUMBER}-${TARGET_BRANCH}}"
BRANCH_NAME="$(printf '%s' "$BRANCH_NAME" | sed 's/[^A-Za-z0-9._-]/-/g')"

mask() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::add-mask::$1" || true; }
emit() { echo "$1"; [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1" >>"$GITHUB_OUTPUT" || true; }

do_pick() {
  mask "$TARGET_TOKEN"; mask "$SOURCE_TOKEN"
  cd "$WORKDIR"
  git config --global user.name  "oss-pick-bot"
  git config --global user.email "oss-pick-bot@users.noreply.github.com"

  emit "branch=$BRANCH_NAME"

  if ! git ls-remote "$tgt_url" HEAD >/dev/null 2>&1; then
    echo "::error::cannot reach ${TARGET_REPO} with the supplied token"
    exit 1
  fi
  # Idempotency: a matching PR (any state) means the pick is done. A branch with
  # NO PR is a stranded push from a prior run whose PR creation failed; delete it
  # and re-pick cleanly (self-heal) instead of skipping forever.
  if git ls-remote --exit-code --heads "$tgt_url" "$BRANCH_NAME" >/dev/null 2>&1; then
    if [ -n "$(GH_TOKEN="$TARGET_TOKEN" gh pr list -R "$TARGET_REPO" --head "$BRANCH_NAME" --state all --json number --jq '.[0].number // empty' 2>/dev/null)" ]; then
      echo "Branch $BRANCH_NAME already has a PR on ${TARGET_REPO}; already picked."
      emit "outcome=already"; return 0
    fi
    echo "::warning::Branch $BRANCH_NAME exists with no PR (stranded); deleting and re-picking."
    git push "$tgt_url" --delete "$BRANCH_NAME" || true
  fi

  git clone "$tgt_url" .
  git remote add source "$src_url"
  git fetch --no-tags source "$SOURCE_REF"
  # Drop the tokened URLs from .git/config before the conflict-resolution agent
  # (Bash/Read over untrusted OSS content) sees this workspace. Remaining git ops
  # here are local; open-pr pushes with an explicit tokened URL.
  git remote set-url origin "https://github.com/${TARGET_REPO}.git"
  git remote set-url source "https://github.com/${SOURCE_REPO}.git"
  git checkout -b "$BRANCH_NAME" "origin/${TARGET_BRANCH}"

  # Squash/single-parent -> plain pick; true merge commit -> -m 1. -x records
  # "(cherry picked from commit ...)" for traceability.
  local parents; parents="$(git show --no-patch --format='%P' "$MERGE_SHA" | wc -w)"
  local rc=0
  if [ "$parents" -ge 2 ]; then
    git cherry-pick -x -m 1 "$MERGE_SHA" || rc=$?
  else
    git cherry-pick -x "$MERGE_SHA" || rc=$?
  fi

  if [ "$rc" -eq 0 ]; then
    echo "Clean cherry-pick."
    emit "outcome=clean"
  elif git diff --name-only --diff-filter=U | grep -q .; then
    echo "Conflicts:"; git diff --name-only --diff-filter=U
    emit "outcome=conflict"
  else
    echo "Cherry-pick empty (already present / superseded)."
    git cherry-pick --abort || true
    emit "outcome=empty"
  fi
}

# Pure-ish text: build the PR title, body, and labels from the source PR
# metadata. Mirrors the enterprise cherry-pick-pull/build-pr-description so the
# merge-queue-bot can parse the body ("**Original Commit SHA**:").
build_pr_text() {
  local pj title body labels
  pj="$(GH_TOKEN="$SOURCE_TOKEN" gh pr view -R "$SOURCE_REPO" "$PR_NUMBER" --json title,body,labels)"
  title="$(jq -r '.title' <<<"$pj")"
  body="$(jq -r '.body // ""' <<<"$pj")"
  labels="$(jq -r '.labels[].name' <<<"$pj")"

  # Strip any prior "[...]" branch tag so we do not stack prefixes.
  local stripped; stripped="$(printf '%s' "$title" | sed 's/^\[.*\] //')"

  # Cross-repo: prefix bare #123 with the source org/repo so links resolve to
  # the source, not the target.
  if [ "$SOURCE_REPO" != "$TARGET_REPO" ]; then
    body="$(printf '%s' "$body" | sed "s/\([^a-zA-Z0-9_.-]\|^\)#\([0-9]\+\)/\1${src_org}\/${src_name}#\2/g")"
  fi
  # Drop sections irrelevant to a pick.
  local section
  for section in "Todos" "Reminder for the reviewer"; do
    body="$(printf '%s\n' "$body" | awk '/^## '"$section"'/{skip=1;next} /^#/&&skip{skip=0} !skip')"
  done

  local prefix
  if [ "$TITLE_PREFIX" = "__DERIVE__" ]; then
    local rel="${TARGET_BRANCH#release-}"; rel="${rel#calient-}"
    prefix="[$rel] "
  else
    prefix="$TITLE_PREFIX"
  fi
  PR_TITLE_OUT="${prefix}${stripped}"

  local conflicts="No conflicts: the cherry-pick applied cleanly."
  if [ "${OUTCOME:-}" = "conflict" ]; then
    if [ -n "${RESOLUTION_REPORT:-}" ] && [ -s "$RESOLUTION_REPORT" ]; then
      conflicts="$(cat "$RESOLUTION_REPORT")"
    else
      # Fail closed on the body text: never claim "clean" for a conflict pick
      # whose report went missing. A human reviewer must scrutinise the diff.
      conflicts=":warning: Conflicts were auto-resolved during the cherry-pick, but the resolution report is missing. Review the diff carefully before merging."
    fi
  fi
  # For a conflict, tuck the (possibly long) AI report into a collapsible block
  # so it does not bury the PR; keep the clean case as a one-liner.
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

  # Labels: optionally carry the source PR's labels (minus the ones that must
  # not propagate), then append EXTRA_LABELS and a severity-tagged conflict
  # label (light/heavy) when the pick had conflicts.
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

do_open_pr() {
  mask "$TARGET_TOKEN"; mask "$SOURCE_TOKEN"
  cd "$WORKDIR"
  export GH_TOKEN="$TARGET_TOKEN"

  # Safety net: an unfinished cherry-pick or leftover markers is real breakage.
  if [ -e .git/CHERRY_PICK_HEAD ]; then
    echo "::error::cherry-pick still in progress; refusing to open PR"; exit 1
  fi
  # No NET change over the base (no new commit, or only empty commits) means the
  # OSS change was fully superseded by Enterprise once resolved. That is a
  # legitimate "nothing to pick" outcome, not an error -- skip without a PR.
  if git diff --quiet "origin/${TARGET_BRANCH}" HEAD 2>/dev/null; then
    echo "::notice::resolution produced no net change over origin/${TARGET_BRANCH}; nothing to pick"
    exit 0
  fi
  local f
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    if grep -qE '^(<<<<<<<|>>>>>>>)' "$f"; then
      echo "::error::conflict markers remain in $f; refusing to open PR"; exit 1
    fi
  done < <(git diff --name-only "origin/${TARGET_BRANCH}..HEAD")

  build_pr_text

  git push "$tgt_url" "HEAD:${BRANCH_NAME}"

  # Create any labels that do not yet exist in the target (never modify
  # existing ones: no --force).
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
  pick)    do_pick ;;
  open-pr) do_open_pr ;;
  *) echo "usage: $0 {pick|open-pr}" >&2; exit 2 ;;
esac
