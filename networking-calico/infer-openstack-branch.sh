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
case "${RELEASE}" in
    caracal )
        RELEASE=2024.1
        ;;
    gazpacho )
        RELEASE=2026.1
        ;;
esac

if [ `git ls-remote -h https://github.com/openstack/${REPO} refs/heads/stable/${RELEASE} | wc -l` = 1 ]; then
    echo stable/${RELEASE}
    exit 0
fi

if [ `git ls-remote -h https://github.com/openstack/${REPO} refs/heads/unmaintained/${RELEASE} | wc -l` = 1 ]; then
    echo unmaintained/${RELEASE}
    exit 0
fi

echo "ERROR: can't identify branch for OpenStack ${RELEASE} in ${REPO}"
exit 1
