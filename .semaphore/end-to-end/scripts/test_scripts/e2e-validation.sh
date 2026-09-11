#!/usr/bin/env bash
set -eo pipefail

# Which tree to validate. Two CI systems each keep their own copy of these
# pipelines and scripts, so the caller says which one it owns; the defaults are
# the Semaphore tree this has always checked.
pipelines_dir="${1:-.semaphore/end-to-end/pipelines}"
scripts_dir="${2:-.semaphore/end-to-end/scripts}"

# Install yq
wget -q https://github.com/mikefarah/yq/releases/download/v4.11.0/yq_linux_amd64 -O yq && chmod +x yq
echo [INFO] Checking pipeline file syntax
FAILED="false"
for file in "$pipelines_dir"/*
do
    echo [INFO] Checking "$file"
    if bash -c "cat $file | ./yq eval > /dev/null"; then
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
# Install shellcheck
wget -q https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz -O shellcheck.tar.xz
tar -xf shellcheck.tar.xz
chmod +x shellcheck-v0.11.0/shellcheck

FAILED="false"
for file in $(find "$scripts_dir" -iname "*.sh" -print0 | xargs -0)
do
    echo [INFO] Checking "$file"
    SHELLCHECK_CMD="shellcheck-v0.11.0/shellcheck --severity=warning $file"
    if [[ $file == *"global_prologue"* ]]; then
        # SC2148 is ignored because the Semaphore global_prologue.sh isn't actually a shell script
        # SC2155 is ignored for the same reason - we need commands on a single line.
        SHELLCHECK_CMD="shellcheck-v0.11.0/shellcheck --severity=warning -e SC2148 -e SC2155 $file"
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

echo "OK"
