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

# Get the location of this script.  Other scripts that we use must be
# in the same location.
scriptdir=$(dirname $(realpath $0))

# Include function library.
. ${scriptdir}/lib.sh
rootdir=`git_repo_root`

pub_steps=
if "${PUBLISH:-false}"; then
    pub_steps="pub_debs pub_rpms"
fi

if [ "${SEMAPHORE_GIT_PR_NUMBER}${SEMAPHORE_GIT_BRANCH}" = master -o -z "${SEMAPHORE_GIT_BRANCH}" ]; then
    # Normally - if not Semaphore, or if this is Semaphore running on
    # the master branch and not for a PR - do all the steps including
    # publication.
    : ${STEPS:=bld_images net_cal felix etcd3gw dnsmasq nettle ${pub_steps}}
else
    # For Semaphore building a PR or a branch other than master, build
    # packages but do not publish them.
    : ${STEPS:=bld_images net_cal felix etcd3gw dnsmasq nettle}
fi

function require_version {
    # VERSION must be specified.  It should be either "master" or
    # "vX.Y.Z".  For "master" we build and publish packages from the HEAD
    # of the master branch of the relevant Calico components.  For
    # "vX.Y.Z" we build and publish packages from that tag in each
    # relevant Calico component.
    test -n "$VERSION"
    echo VERSION is $VERSION

    # Determine REPO_NAME.
    if [ $VERSION = master ]; then
	: ${REPO_NAME:=master}
	: ${NETWORKING_CALICO_CHECKOUT:=master}
	: ${FELIX_CHECKOUT:=master}
    elif [[ $VERSION =~ ^release-v ]]; then
	: ${REPO_NAME:=testing}
	: ${NETWORKING_CALICO_CHECKOUT:=${VERSION}}
	: ${FELIX_CHECKOUT:=${VERSION}}
    elif [[ $VERSION =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-python2)?$ ]]; then
	MAJOR=${BASH_REMATCH[1]}
	MINOR=${BASH_REMATCH[2]}
	PATCH=${BASH_REMATCH[3]}
	PY2SUFFIX=${BASH_REMATCH[4]}
	: ${REPO_NAME:=calico-${MAJOR}.${MINOR}${PY2SUFFIX}}
	: ${NETWORKING_CALICO_CHECKOUT:=v${MAJOR}.${MINOR}.${PATCH}${PY2SUFFIX}}
	: ${FELIX_CHECKOUT:=v${MAJOR}.${MINOR}.${PATCH}}
    else
	echo "ERROR: Unhandled VERSION \"${VERSION}\""
	exit 1
    fi
    export REPO_NAME
    echo REPO_NAME is $REPO_NAME
}

function require_repo_name {
    test -n "$REPO_NAME" || require_version
}

function require_rpm_host_vars {
    # HOST and GCLOUD_ARGS must be set to indicate the RPM host, and a
    # gcloud identity that permits logging into that host.
    test -n "$GCLOUD_ARGS"
    echo GCLOUD_ARGS is "$GCLOUD_ARGS"
    test -n "$HOST"
    echo HOST is $HOST
}

function require_deb_secret_key {
    # SECRET_KEY must be a file containing the GPG secret key for a member
    # of the Project Calico team on Launchpad.
    test -n "$SECRET_KEY"
    echo SECRET_KEY is $SECRET_KEY
}

# Decide target arch; by default the same as the native arch here.  We
# conventionally say "amd64", where uname says "x86_64".
ARCH=${ARCH:-`uname -m`}
if [ $ARCH = x86_64 ]; then
    ARCH=amd64
fi

# Conditions that we check before running any of the requested steps.

function precheck_bld_images {
    :
}

function precheck_net_cal {
    test -n "${NETWORKING_CALICO_CHECKOUT}" || require_version
}

function precheck_felix {
    test -n "${FELIX_CHECKOUT}" || require_version
}

function precheck_etcd3gw {
    :
}

function precheck_dnsmasq {
    :
}

function precheck_nettle {
    :
}

function precheck_pub_debs {
    # Check the PPA exists.
    require_repo_name
    wget -O - https://launchpad.net/~project-calico/+archive/ubuntu/${REPO_NAME} | grep -F "PPA description" || {
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

    # We'll need a secret key to upload new source packages.
    require_deb_secret_key
}

function precheck_pub_rpms {
    require_repo_name
    require_rpm_host_vars
}

# Execution of the requested steps.

function docker_run_rm {
    docker run --rm --user `id -u`:`id -g` -v $(dirname `pwd`):/code -w /code/$(basename `pwd`) "$@"
}

function do_bld_images {
    # Build the docker images that we use for building for each target platform.
    pushd ${rootdir}/docker-build-images
    docker build -f ubuntu-trusty-build.Dockerfile.${ARCH} -t calico-build/trusty .
    docker build -f ubuntu-xenial-build.Dockerfile.${ARCH} -t calico-build/xenial .
    docker build -f ubuntu-bionic-build.Dockerfile.${ARCH} -t calico-build/bionic .
    docker build -f ubuntu-focal-build.Dockerfile.${ARCH} -t calico-build/focal .
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
}

function do_net_cal {
    # Build networking-calico packages.
    pushd ${rootdir}
    rm -rf networking-calico
    NETWORKING_CALICO_REPO=${NETWORKING_CALICO_REPO:-https://github.com/projectcalico/networking-calico.git}
    git clone $NETWORKING_CALICO_REPO -b $NETWORKING_CALICO_CHECKOUT
    cd networking-calico
    PKG_NAME=networking-calico \
	    NAME=networking-calico \
	    DEB_EPOCH=1: \
	    ../utils/make-packages.sh deb rpm
    popd
}

function do_felix {
    # Build Felix packages.
    pushd ${rootdir}
    rm -rf felix
    FELIX_REPO=${FELIX_REPO:-https://github.com/projectcalico/felix.git}
    git clone $FELIX_REPO -b $FELIX_CHECKOUT felix
    cd felix
    # We build the Felix binary and include it in our source package
    # content, because it's infeasible to work out a set of Debian and
    # RPM golang build dependencies that is exactly equivalent to our
    # containerized builds.
    make bin/calico-felix
    # Remove all the files that were added by that build, except for the
    # bin/calico-felix binary.
    rm -f bin/calico-felix-amd64
    if grep -q build-bpf Makefile; then
      make build-bpf
      rm -f bpf-gpl/bin/test_*
    fi
    # Override dpkg's default file exclusions, otherwise our binaries won't get included (and some
    # generated files will).
    PKG_NAME=felix \
	    NAME=Felix \
	    RPM_TAR_ARGS='--exclude=bin/calico-felix-* --exclude=.gitignore --exclude=*.d --exclude=*.ll --exclude=.go-pkg-cache --exclude=vendor --exclude=report' \
	    DPKG_EXCL="-I'bin/calico-felix-*' -I.git -I.gitignore -I'*.d' -I'*.ll' -I.go-pkg-cache -I.git -Ivendor -Ireport" \
	    ../utils/make-packages.sh deb rpm
    popd
}

function do_etcd3gw {
    pushd ${rootdir}/etcd3gw
    if ${PACKAGE_ETCD3GW:-false}; then
	# When PACKAGE_ETCD3GW is explicitly specified, build RPM Python 2 packages for etcd3gw.
	PKG_NAME=python-etcd3gw ../utils/make-packages.sh rpm
    else
        # Otherwise, no-op.  We don't have Python 3 RPM packaging for etcd3gw, so it makes sense to
	# retreat to the same solution as for Debian/Ubuntu: don't build etcd3gw packages, and
	# instead document that 'pip install' should be used to install etcd3gw.
	:
    fi
    popd
}

function do_dnsmasq {
    pushd ${rootdir}
    rm -rf dnsmasq
    git clone https://github.com/projectcalico/calico-dnsmasq.git dnsmasq
    cd dnsmasq

    # Ubuntu Trusty
    git checkout 2.79test1calico1-3-trusty
    docker_run_rm calico-build/trusty dpkg-buildpackage -I -S

    # Ubuntu Xenial
    git checkout 2.79test1calico1-2-xenial
    sed -i s/trusty/xenial/g debian/changelog
    git commit -a -m "switch trusty to xenial in debian/changelog" --author="Marvin <marvin@tigera.io>"
    docker_run_rm calico-build/xenial dpkg-buildpackage -I -S

    # CentOS/RHEL 7
    git checkout origin/rpm_2.79
    docker_run_rm -e EL_VERSION=el7 calico-build/centos7 ../rpm/build-rpms

    popd
}

function do_nettle {
    # nettle-3.3 for Ubuntu Xenial - At the point checked out, the
    # Dnsmasq code had this content in debian/shlibs.local:
    #
    # libnettle 6 libnettle6 (>= 3.3)
    #
    # This causes the built binary package to depend on libnettle6 >=
    # 3.3, which is problematic because that version is not available
    # in Xenial.  So we also build and upload nettle 3.3 to our PPA.
    pushd ${rootdir}
    rm -rf nettle
    mkdir nettle
    cd nettle
    wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/nettle/3.3-1/nettle_3.3-1.dsc
    wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/nettle/3.3-1/nettle_3.3.orig.tar.gz
    wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/nettle/3.3-1/nettle_3.3-1.debian.tar.xz
    docker_run_rm calico-build/xenial dpkg-source -x nettle_3.3-1.dsc
    rm -rf ../nettle-3.3
    mv nettle-3.3 ../
    cp -a nettle_3.3.orig.tar.gz ../
    cd ../nettle-3.3
    sed -i '1 s/unstable/xenial/' debian/changelog
    docker_run_rm calico-build/xenial dpkg-buildpackage -S

    popd
}

function do_pub_debs {
    # Publish Debian packages.
    pushd ${rootdir}
    ./utils/publish-debs.sh
    popd
}

function do_pub_rpms {
    # Create the RPM repo, if it doesn't already exist, on binaries.
    ensure_repo_exists ${REPO_NAME}

    # Publish RPM packages.  Note, this includes updating the RPM repo
    # metadata.
    pushd ${rootdir}
    ./utils/publish-rpms.sh
    popd
}

# Do prechecks for requested steps.
for step in ${STEPS}; do
    eval precheck_${step}
done

# Execute requested steps.
for step in ${STEPS}; do
    eval do_${step}
done
