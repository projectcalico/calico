#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# Polls a Semaphore workflow until completion, timeout, or stop.
# Required env vars: WORKFLOW_ID, SEMAPHORE_ORG, SEMAPHORE_TOKEN
set -euo pipefail

START_TIME=$(date +%s)

while true; do
    RESPONSE=$(curl -s -f \
        "https://${SEMAPHORE_ORG}.semaphoreci.com/api/v1alpha/plumber-workflows/${WORKFLOW_ID}" \
        -H "Authorization: Token ${SEMAPHORE_TOKEN}")

    STATE=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['workflow']['state'])" 2>/dev/null || echo "UNKNOWN")
    RESULT=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['workflow'].get('result', ''))" 2>/dev/null || echo "")

    echo "Workflow $WORKFLOW_ID: state=$STATE result=$RESULT"

    if [[ "$STATE" == "DONE" ]]; then
        echo "final_result=$RESULT" >> "$GITHUB_OUTPUT"
        echo "final_state=$STATE" >> "$GITHUB_OUTPUT"
        break
    fi

    if [[ "$STATE" == "STOPPING" || "$STATE" == "STOPPED" ]]; then
        echo "final_result=STOPPED" >> "$GITHUB_OUTPUT"
        echo "final_state=$STATE" >> "$GITHUB_OUTPUT"
        break
    fi

    NOW=$(date +%s)
    ELAPSED=$(( NOW - START_TIME ))
    if (( ELAPSED > 14400 )); then
        echo "final_result=TIMEOUT" >> "$GITHUB_OUTPUT"
        echo "final_state=TIMEOUT" >> "$GITHUB_OUTPUT"
        break
    fi

    sleep 60
done

END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))
DURATION_MIN=$(( DURATION / 60 ))
echo "duration_minutes=$DURATION_MIN" >> "$GITHUB_OUTPUT"
