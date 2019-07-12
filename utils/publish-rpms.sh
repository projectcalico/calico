#!/bin/bash -ex

# publish-rpms.sh
#
# Publish RPMs under dist/rpms, to an RPM repo on
# binaries.projectcalico.org.

REPO_NAME=${REPO_NAME:-master}

# Get the location of this script and include common function library.
scriptdir=$(dirname $(readlink -f $0))
. ${scriptdir}/lib.sh

# Create the repository on binaries, in case it does not already exist.
ensure_repo_exists ${REPO_NAME}

# Copy RPMs here to repository on binaries.
copy_rpms_to_host ${REPO_NAME}

# Update repository metadata.
update_repo_metadata ${REPO_NAME}
