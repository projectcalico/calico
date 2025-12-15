#!/bin/bash

# Infer the current branch name for the OpenStack release $1 in repo name $2.
if [ $# -ne 2 ]; then
    echo "Usage: $0 <openstack release> <repo name>"
    echo
    echo "For example: $0 caracal devstack"
    exit 1
fi
RELEASE=$1
REPO=$2

# Translate modern OpenStack release names to their YEAR.NUMBER form.
FORMAL_RELEASE=${RELEASE}
case "${RELEASE}" in
    caracal )
        FORMAL_RELEASE=2024.1
        ;;
    gazpacho )
        FORMAL_RELEASE=2026.1
        ;;
esac

if [ $(git ls-remote -h https://github.com/openstack/${REPO} refs/heads/stable/${FORMAL_RELEASE} | wc -l) = 1 ]; then
    echo stable/${FORMAL_RELEASE}
    exit 0
fi

if [ $(git ls-remote -h https://github.com/openstack/${REPO} refs/heads/unmaintained/${FORMAL_RELEASE} | wc -l) = 1 ]; then
    echo unmaintained/${FORMAL_RELEASE}
    exit 0
fi

echo "ERROR: can't identify branch for OpenStack ${RELEASE} in ${REPO}"
exit 1
