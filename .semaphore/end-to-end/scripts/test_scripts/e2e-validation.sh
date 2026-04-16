#!/usr/bin/env bash
set -eo pipefail

echo [INFO] Checking pipeline file syntax
FAILED="false"
for file in .semaphore/end-to-end/pipelines/*
do
    echo [INFO] Checking "$file"
    if bash -c "cat $file | yq eval > /dev/null"; then
        echo "OK"
    else
        echo "$file FAILED validation"
        FAILED="true"
    fi
done

if [ $FAILED = "true" ]; then
    exit 1
fi

echo [INFO] Checking *.sh file syntax
# Install latest shellcheck
SC_VER=$(curl -sSf https://api.github.com/repos/koalaman/shellcheck/releases/latest | jq -r '.tag_name')
curl -sSfL "https://github.com/koalaman/shellcheck/releases/latest/download/shellcheck-${SC_VER}.linux.x86_64.tar.xz" | tar xJ
SHELLCHECK="shellcheck-${SC_VER}/shellcheck"

FAILED="false"
for file in $(find .semaphore/end-to-end/scripts -iname "*.sh" -print0 | xargs -0)
do
    echo [INFO] Checking "$file"
    SHELLCHECK_CMD="$SHELLCHECK --severity=warning $file"
    if [[ $file == *"global_prologue"* ]]; then
        # SC2148 is ignored because .semaphore/end-to-end/scripts/global_prologue.sh isn't actually a shell script
        # SC2155 is ignored because .semaphore/end-to-end/scripts/global_prologue.sh isn't actually a shell script - we need commands on a single line.
        SHELLCHECK_CMD="$SHELLCHECK --severity=warning -e SC2148 -e SC2155 $file"
    fi

    if $SHELLCHECK_CMD; then
        echo "OK"
    else
        echo "$file FAILED validation"
        FAILED="true"
    fi
done
if [ $FAILED = "true" ]; then
    exit 1
fi
