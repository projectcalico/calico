#!/usr/bin/env bash
set -eo pipefail

pipelines_dir="${1:-.argoci/cron}"
scripts_dir="${2:-.argoci/scripts}"

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
        # SC2148/SC2155 are ignored because global_prologue.sh is a list of commands, not a script.
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
