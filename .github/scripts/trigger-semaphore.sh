#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# Triggers a Semaphore pipeline and extracts the workflow ID.
# Required env vars: SEMAPHORE_ORG, SEMAPHORE_TOKEN, SEMAPHORE_PROJECT_ID,
#   BRANCH, SHA, PIPELINE_FILE, TAG, E2E_IMAGE, LABEL_FILTER
set -euo pipefail

HTTP_CODE=$(curl -s -o /tmp/sem-response.json -w "%{http_code}" -X POST \
    "https://${SEMAPHORE_ORG}.semaphoreci.com/api/v1alpha/plumber-workflows" \
    -H "Authorization: Token ${SEMAPHORE_TOKEN}" \
    -H "Content-Type: application/json" \
    -d @- <<EOF
{
    "project_id": "${SEMAPHORE_PROJECT_ID}",
    "reference": "${BRANCH}",
    "commit_sha": "${SHA}",
    "pipeline_file": "${PIPELINE_FILE}",
    "parameters": {
        "IMAGE_REGISTRY": "gcr.io",
        "IMAGE_PATH": "unique-caldron-775/ci/calico",
        "IMAGE_TAG": "${TAG}",
        "E2E_IMAGE": "${E2E_IMAGE}",
        "LABEL_FILTER": "${LABEL_FILTER}"
    }
}
EOF
)

RESPONSE=$(cat /tmp/sem-response.json)
echo "Semaphore API response (HTTP ${HTTP_CODE}): ${RESPONSE}"

if [[ "$HTTP_CODE" -ge 400 ]]; then
    echo "::error::Semaphore API returned HTTP ${HTTP_CODE}: ${RESPONSE}"
    exit 1
fi

WORKFLOW_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['workflow_id'])")
echo "workflow_id=$WORKFLOW_ID" >> "$GITHUB_OUTPUT"

SEMAPHORE_URL="https://${SEMAPHORE_ORG}.semaphoreci.com/workflows/${WORKFLOW_ID}"
echo "semaphore_url=$SEMAPHORE_URL" >> "$GITHUB_OUTPUT"
