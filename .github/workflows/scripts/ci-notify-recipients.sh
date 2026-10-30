#!/usr/bin/env bash
#
# Prints the Slack member IDs to DM about a PR, one per line.
#
#   ci-notify-recipients.sh <pr.json>
#
# pr.json: {"login": ..., "labels": [names], "assignees": [logins]}
# CI_NOTIFY_MAP          "login:slackid, login:slackid, ..." opt-in map.
# BOT_AUTHORS            comma-separated logins that open PRs on someone's
#                        behalf.
# ASSIGNEE_OWNED_LABELS  comma-separated labels; a bot PR carrying one is owned
#                        by its assignees. People add these labels by hand too.
set -o errexit -o nounset -o pipefail

pr_json="${1:?usage: $0 <pr.json>}"

logins="$(jq -r --arg bots "${BOT_AUTHORS:-}" --arg owned "${ASSIGNEE_OWNED_LABELS:-}" '
  def list: split(",") | map(gsub("\\s"; "") | ascii_downcase) | map(select(. != ""));
  ($bots | list) as $b | ($owned | list) as $o
  | if ((.login // "") | ascii_downcase | IN($b[]))
       and any((.labels // [])[]; ascii_downcase | IN($o[]))
       and ((.assignees // []) | length) > 0
    then .assignees[] else (.login // empty) end' "$pr_json")"

for login in $logins; do
  # Per-record whitespace strip: a global `tr -d` would join the entries. GitHub
  # logins are case-insensitive.
  id="$(printf '%s' "${CI_NOTIFY_MAP:-}" \
    | tr ',' '\n' \
    | awk -F: -v u="$login" '{gsub(/[[:space:]]/, "")} !found && tolower($1)==tolower(u) {print $2; found=1}')"
  if [[ -n "$id" ]]; then
    echo "$id"
  else
    echo "::notice::'$login' not in CI_NOTIFY_MAP — skipping" >&2
  fi
done | sort -u
