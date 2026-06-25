#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# Parses a /e2e comment into profile and label-filter outputs.
# Inputs:  COMMENT (env var) - the comment body
# Outputs: profile, label_filter (written to GITHUB_OUTPUT)
set -euo pipefail

PROFILE=$(echo "$COMMENT" | awk '{print $2}')

LABEL_FILTER=""
if echo "$COMMENT" | grep -qE '\-\-label-filter='; then
    LABEL_FILTER=$(echo "$COMMENT" | sed -nE 's/.*--label-filter="([^"]+)".*/\1/p')
    if [[ -z "$LABEL_FILTER" ]]; then
        LABEL_FILTER=$(echo "$COMMENT" | sed -nE 's/.*--label-filter=([^ ]+).*/\1/p')
    fi
fi

echo "profile=$PROFILE" >> "$GITHUB_OUTPUT"
echo "label_filter=$LABEL_FILTER" >> "$GITHUB_OUTPUT"
