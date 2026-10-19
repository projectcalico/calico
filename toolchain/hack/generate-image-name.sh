#!/bin/bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Names a GCE image after the calico/go-build tag it carries, so the two match
# by eye. Illegal characters fold to hyphens: GCE names are RFC1035, 63 at most.
# -m sets a lower cap. GKE allows 39 for a secondary boot disk, and it checks
# that only when a node pool attaches the image, long after the build.
#
# A release build is a master or release-v* build in ArgoCI that is not a PR.
# Its family is per go-build tag, derived exactly as tigera/cc-utils derives
# a createVM step's family from .argoci/config.yaml's goBuildVersion: drop the
# words "llvm" and "k8s", then fold. Any other build uses its PR or branch
# instead of the tag, so it never moves a family that CI boots from. Local runs
# are never release builds.
#
#   build              image name                          family
#   release (master)   ci-base-1-27-2-llvm21-1-8-9cc1214   ci-base-1-27-2-21-1-8
#   PR 1234            ci-base-pr-1234-9cc1214             ci-base-pr-1234
#   local branch foo   ci-base-foo-9cc1214                 ci-base-foo
#
# A family resolves to its newest member, so every name carries the commit.
# Nothing is ever deleted to make room, and a rebuild of the same go-build tag
# just moves the family.
#
#   generate-image-name.sh -p <prefix> [-t <go-build tag>] [-m <max>] [-F]

set -eu

prefix=""
tag=""
max_len=63
want_family=false

while getopts ":p:t:m:F" opt; do
    case $opt in
    p) prefix="$OPTARG" ;;
    t) tag="$OPTARG" ;;
    m) max_len="$OPTARG" ;;
    F) want_family=true ;;
    :)
        echo "option: -$OPTARG requires an argument" >&2
        exit 1
        ;;
    *)
        echo "invalid option: -$OPTARG" >&2
        exit 1
        ;;
    esac
done

if [[ -z $prefix ]]; then
    echo "-p <prefix> is required" >&2
    exit 1
fi

here="$(cd "$(dirname "$0")" && pwd)"
toolchain="$(cd "$here/.." && pwd)"

# Lowercase, fold to a legal RFC1035 tail: no runs of hyphens, none leading or
# trailing.
fold_name() {
    echo "$1" |
        tr '[:upper:]' '[:lower:]' |
        sed -e 's/[^a-z0-9-]/-/g' -e 's/--*/-/g' -e 's/^-//' -e 's/-$//'
}

check_name() {
    local what=$1 name=$2 limit=$3
    if [[ ${#name} -gt $limit ]]; then
        echo "$what is ${#name} characters, over the limit of $limit: $name" >&2
        exit 1
    fi
    if ! [[ $name =~ ^[a-z]([-a-z0-9]*[a-z0-9])?$ ]]; then
        echo "not a valid GCE $what: $name" >&2
        exit 1
    fi
}

release=false
ref=""
if [[ -n ${CI_GIT_REF_TYPE:-} ]]; then
    if [[ $CI_GIT_REF_TYPE == PR ]]; then
        ref="pr-${CI_GIT_PR_NUMBER:?CI_GIT_PR_NUMBER is unset on a PR build}"
    elif [[ ${CI_GIT_BRANCH:-} == master || ${CI_GIT_BRANCH:-} == release-v* ]]; then
        release=true
    else
        ref="${CI_GIT_BRANCH:?CI_GIT_BRANCH is unset}"
    fi
elif branch="$(git -C "$here" rev-parse --abbrev-ref HEAD 2>/dev/null)" && [[ -n $branch && $branch != HEAD ]]; then
    ref="$branch"
else
    echo "cannot name a local build on a detached HEAD; check out a branch" >&2
    exit 1
fi

if [[ $release == true ]]; then
    if [[ -z $tag ]]; then
        tag="$(make --no-print-directory -s -C "$toolchain/images/go-build" print-tag)"
    fi
    if [[ -z $tag ]]; then
        echo "the go-build tag is empty" >&2
        exit 1
    fi
fi

if [[ $want_family == true ]]; then
    if [[ $release == true ]]; then
        stripped="${tag//llvm/}"
        family="${prefix}-$(fold_name "${stripped//k8s/}")"
    else
        family="${prefix}-$(fold_name "$ref")"
    fi
    check_name family "$family" 63
    echo "$family"
    exit 0
fi

sha="${CI_GIT_SHA:-$(git -C "$here" rev-parse HEAD 2>/dev/null || true)}"
if [[ -z $sha ]]; then
    echo "cannot determine the commit; set CI_GIT_SHA" >&2
    exit 1
fi

if [[ $release == true ]]; then
    name="${prefix}-$(fold_name "$tag")-${sha:0:7}"
else
    name="${prefix}-$(fold_name "$ref")-${sha:0:7}"
fi
check_name "image name" "$name" "$max_len"
echo "$name"
