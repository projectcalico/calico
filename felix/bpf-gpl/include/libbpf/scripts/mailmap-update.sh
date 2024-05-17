#!/usr/bin/env bash

set -eu

usage () {
    echo "USAGE: ./mailmap-update.sh <libbpf-repo> <linux-repo>"
    exit 1
}

LIBBPF_REPO="${1-""}"
LINUX_REPO="${2-""}"

if [ -z "${LIBBPF_REPO}" ] || [ -z "${LINUX_REPO}" ]; then
    echo "Error: libbpf or linux repos are not specified"
    usage
fi

LIBBPF_MAILMAP="${LIBBPF_REPO}/.mailmap"
LINUX_MAILMAP="${LINUX_REPO}/.mailmap"

tmpfile="$(mktemp)"
cleanup() {
    rm -f "${tmpfile}"
}
trap cleanup EXIT

grep_lines() {
    local pattern="$1"
    local file="$2"
    grep "${pattern}" "${file}" || true
}

while read -r email; do
    grep_lines "${email}$" "${LINUX_MAILMAP}" >> "${tmpfile}"
done < <(git log --format='<%ae>' | sort -u)

sort -u "${tmpfile}" > "${LIBBPF_MAILMAP}"
