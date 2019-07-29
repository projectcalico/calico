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

# VERSION must be specified.  It should be either "master" or
# "vX.Y.Z".  For "master" we build and publish packages from the HEAD
# of the master branch of the relevant Calico components.  For
# "vX.Y.Z" we build and publish packages from that tag in each
# relevant Calico component.
test -n "$VERSION"
echo VERSION is $VERSION

# Determine REPO_NAME.
if [ $VERSION = master ]; then
    REPO_NAME=master
    NETWORKING_CALICO_CHECKOUT=master
    FELIX_CHECKOUT=master
elif [[ $VERSION =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    MAJOR=${BASH_REMATCH[1]}
    MINOR=${BASH_REMATCH[2]}
    PATCH=${BASH_REMATCH[3]}
    REPO_NAME=calico-${MAJOR}.${MINOR}
    NETWORKING_CALICO_CHECKOUT=${MAJOR}.${MINOR}.${PATCH}
    FELIX_CHECKOUT=v${MAJOR}.${MINOR}.${PATCH}
else
    echo "ERROR: Unhandled VERSION \"${VERSION}\""
    exit 1
fi
export REPO_NAME
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
rootdir=`git_repo_root`

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

# Decide target arch; by default the same as the native arch here.  We
# conventionally say "amd64", where uname says "x86_64".
ARCH=${ARCH:-`uname -m`}
if [ $ARCH = x86_64 ]; then
    ARCH=amd64
fi

# Build the docker images that we use for building for each target platform.
pushd ${rootdir}/docker-build-images
docker build -f ubuntu-trusty-build.Dockerfile.${ARCH} -t calico-build/trusty .
docker build -f ubuntu-xenial-build.Dockerfile.${ARCH} -t calico-build/xenial .
docker build -f ubuntu-bionic-build.Dockerfile.${ARCH} -t calico-build/bionic .
docker build --build-arg=UID=`id -u` --build-arg=GID=`id -g` -f centos7-build.Dockerfile.${ARCH} -t calico-build/centos7 .
popd
if [ $ARCH = ppc64le ]; then
    # Some commands that would typically be run at container build
    # time must be run in a privileged container.
    docker rm -f centos7Tmp
    docker run --privileged --name=centos7Tmp calico-build/centos7 \
	   /bin/bash -c "/setup-user; /install-centos-build-deps"
    docker commit centos7Tmp calico-build/centos7:latest
fi

# Build networking-calico packages.
pushd ${rootdir}
rm -rf networking-calico
NETWORKING_CALICO_REPO=${NETWORKING_CALICO_REPO:-https://opendev.org/openstack/networking-calico.git}
git clone $NETWORKING_CALICO_REPO -b $NETWORKING_CALICO_CHECKOUT
cd networking-calico
../utils/make-packages deb rpm
popd

# Publish all packages.  Note, this includes updating the RPM repo
# metadata.
pushd ${rootdir}
./utils/publish-debs.sh
./utils/publish-rpms.sh
popd
