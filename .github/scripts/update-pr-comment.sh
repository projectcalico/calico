#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# Creates or updates a PR comment via the GitHub API.
# Usage: update-pr-comment.sh <repo> <issue_number> <body> [comment_id]
# If comment_id is provided, PATCHes the existing comment.
# Otherwise, POSTs a new comment and prints the new comment ID.
set -euo pipefail

REPO="$1"
ISSUE_NUMBER="$2"
BODY="$3"
COMMENT_ID="${4:-}"

if [[ -n "$COMMENT_ID" ]]; then
    gh api "repos/${REPO}/issues/comments/${COMMENT_ID}" \
        -X PATCH -f "body=${BODY}"
else
    gh api "repos/${REPO}/issues/${ISSUE_NUMBER}/comments" \
        -X POST -f "body=${BODY}" --jq '.id'
fi
