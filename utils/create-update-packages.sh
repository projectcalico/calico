#!/bin/bash -ex

# Do everything that's needed to create or update the Calico PPA and
# RPM repo named ${REPO_NAME}, so that those provide packages for the
# latest relevant Calico code.
#
# - Check the PPA exists.  If not, print instructions for how to
#   create it, and bail out.
#
# - Create the RPM repo, if it doesn't already exist, on binaries.
#
# - Build and publish all required packages, if their underlying code
#   has changed since what is already published in the target
#   PPA/repo.
#
# - Update the RPM repo metadata.

# REPO_NAME must be specified.  It should be either "master" or
# "calico-X.Y".  For "master" we build and publish packages from the
# HEAD of the master branch of the relevant Calico components.  For
# "calico-X.Y" we identify the latest tag of the relevant Calico
# components that matches X.Y, and build and publish packages from
# those points.
test -n "$REPO_NAME"
echo REPO_NAME is $REPO_NAME

# SECRET_KEY must be a file containing the GPG secret key for a member
# of the Project Calico team on Launchpad.
test -n "$SECRET_KEY"
echo SECRET_KEY is $SECRET_KEY

# HOST and GCLOUD_ARGS must be set to indicate the RPM host, and a
# gcloud identity that permits logging into that host.
test -n "$GCLOUD_ARGS"
echo GCLOUD_ARGS is "$GCLOUD_ARGS"
test -n "$HOST"
echo HOST is $HOST

# Get the location of this script.  Other scripts that we use must be
# in the same location.
scriptdir=$(dirname $(realpath $0))

# Include function library.
. ${scriptdir}/lib.sh

# Check the PPA exists.
wget -O /dev/null http://ppa.launchpad.net/project-calico/${REPO_NAME}/ubuntu/dists/bionic/main/source/Sources.gz || {
    cat <<EOF

ERROR: PPA for ${REPO_NAME} does not exist.  Create it, then rerun this job.

(Apologies, this is the only remaining manual step.  To create the PPA:

- Go to https://launchpad.net/~project-calico and note the name and
  description of the PPA for the previous Calico release series.

- Create a new PPA with similar name and description but for the new
  series.)

EOF
    exit 1
}

# Create the RPM repo, if it doesn't already exist, on binaries.
ensure_repo_exists ${REPO_NAME}

# Build and publish networking-calico packages.
make deb rpm

# Publish Debian packages.
./utils/publish-debs.sh

# Publish RPMs.  Note, this includes updating the RPM repo metadata.
./utils/publish-rpms.sh
