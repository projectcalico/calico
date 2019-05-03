#!/bin/bash -ex

# publish-rpms.sh
#
# Publish RPMs under dist/rpms, to the 'master' repo on
# binaries.projectcalico.org.

# Get the location of this script and include common function library.
scriptdir=$(dirname $(readlink -f $0))
. ${scriptdir}/lib.sh

# Create the master repository on binaries, in case it does not already exist.
ensure_repo_exists master

# Copy RPMs here to master repository on binaries.
copy_rpms_to_host master

# Update repository metadata.
update_repo_metadata master
