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
# ASSIGNEE_OWNED_LABELS  comma-separated labels. A PR a bot opened that carries
#                        one is owned by its assignees, who get the DM as if
#                        they had opened it. The label alone is not enough:
#                        people open PRs with these labels by hand too.
set -o errexit -o nounset -o pipefail

pr_json="${1:?usage: $0 <pr.json>}"

logins="$(jq -r --arg bots "${BOT_AUTHORS:-}" --arg owned "${ASSIGNEE_OWNED_LABELS:-}" '
  def list: split(",") | map(gsub("\\s"; "") | ascii_downcase) | map(select(. != ""));
  ($bots | list) as $b | ($owned | list) as $o
  | if (.login | ascii_downcase | IN($b[]))
       and any((.labels // [])[]; ascii_downcase | IN($o[]))
       and ((.assignees // []) | length) > 0
    then .assignees[] else .login end' "$pr_json")"

for login in $logins; do
  # Logins are [A-Za-z0-9-] and Slack IDs are [A-Z0-9], so ':' is an
  # unambiguous delimiter. Whitespace is stripped per record: a global
  # `tr -d '[:space:]'` would also join the entries into one line. GitHub
  # logins are case-insensitive, and the map is written by hand.
  id="$(printf '%s' "${CI_NOTIFY_MAP:-}" \
    | tr ',' '\n' \
    | awk -F: -v u="$login" '{gsub(/[[:space:]]/, "")} tolower($1)==tolower(u) {print $2; exit}')"
  if [[ -n "$id" ]]; then
    echo "$id"
  else
    echo "::notice::'$login' not in CI_NOTIFY_MAP — skipping" >&2
  fi
done | sort -u
