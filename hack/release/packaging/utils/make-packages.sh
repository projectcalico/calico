#!/bin/bash -e

# Build Debian and RPM packages for the current Git HEAD.
#
# Usage: make-packages.sh [deb] [rpm]

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname $(realpath $0))

# Get the location of the rpm builder script.
rpmDir=$(dirname $scriptdir)/rpm

# Include function library.
. ${scriptdir}/lib.sh

# Get the version based on Git state, and the Git commit ID.
version=${FORCE_VERSION:-`git_auto_version`}
version=`strip_v ${version}`
sha=`git_commit_id`

DOCKER_RUN_RM="docker run --rm --user $(id -u):$(id -g) -v $rpmDir:/rpm -v $(dirname `pwd`):/code -w /code/$(basename `pwd`)"

# Determine if this is a release (i.e. corresponds exactly to a Git tag) or a
# snapshot.
release=true
case ${version} in
    *.post* )
	release=false
	;;
esac

if [ ${PKG_NAME} = networking-calico ]; then
    sed -i "s/version=\"0.0.0\"/version=\"${version}\"/" setup.py
fi

# Build the requested package types.
for package_type in "$@"; do

    case ${package_type} in

	deb )
	    if [ "${PKG_NAME}" = felix ]; then
	        # Felix is built with RHEL/UBI and links against libpcap.so.1. We need this patchelf
	        # until Debian changes the soname from .0.8 to .1.
	        # FIXME remove the following patchelf command once Debian dependency is updated.
	        patchelf --replace-needed libpcap.so.1 libpcap.so.0.8 bin/calico-felix
	    fi

	    # The Debian version that we are about to generate.
	    debver=${FORCE_VERSION_DEB:-`git_version_to_deb ${version}`}
	    debver=`strip_v ${debver}`

	    # Current time in Debian changelog format; e.g. Wed, 02
	    # Mar 2016 14:08:51 +0000.
	    timestamp=`date "+%a, %d %b %Y %H:%M:%S %z"`
	    for series in focal jammy; do
		{
			if ${release}; then
				changelog_message="* ${NAME} v${version} (from Git commit ${sha})."
			else
				changelog_message="* Development snapshot (from Git commit ${sha})."
			fi
		    cat <<EOF
${PKG_NAME} (${DEB_EPOCH}${debver}-$series) $series; urgency=low

  ${changelog_message}

 -- Daniel Fox <dan.fox@tigera.io>  ${timestamp}
EOF
		} > debian/changelog

		excludes="${DPKG_EXCL:--I}"

		${DOCKER_RUN_RM} calico-build/${series} dpkg-buildpackage ${excludes} -S -d | ts "[build $series]"
	    done

	    cat <<EOF

    +---------------------------------------------------------------------------+
    | Debs have been built.                                                     |
    +---------------------------------------------------------------------------+

EOF
	    ;;

	rpm )
	    rpm_spec=rpm/${PKG_NAME}.spec
	    if [ -f ${rpm_spec}.in ]; then
		debver=${FORCE_VERSION_RPM:-`git_version_to_rpm ${version}`}
		debver=`strip_v ${debver}`
		cp -f ${rpm_spec}.in ${rpm_spec}

		# Generate RPM version and release.
		IFS=_ read ver qual <<< ${debver}
		if test "${qual}"; then
		    rpmver=${ver}
		    rpmrel=0.1.${qual}
		else
		    rpmver=${ver}
		    rpmrel=1
		fi

		# Update the Version: and Release: lines.
		sed -i "s/^Version:.*$/Version:        ${rpmver#*:}/" ${rpm_spec}
		sed -i "s/^Release:.*$/Release:        ${rpmrel}%{?dist}/" ${rpm_spec}

		# Add a stanza to the %changelog section.
		timestamp=`date "+%a %b %d %Y"`
		{
		    cat <<EOF
* ${timestamp} Neil Jerram <neil@tigera.io> ${rpmver}-${rpmrel}
EOF
		    if ${release}; then
			cat <<EOF
  - ${NAME} v${version} (from Git commit ${sha}).
EOF
		    else
			cat <<EOF
  - Development snapshot (from Git commit ${sha}).
EOF
		    fi
		    echo

		} | sed -i '/^%changelog/ r /dev/stdin' ${rpm_spec}
	    fi

	    elversions=7
	    for elversion in ${elversions}; do
		# Skip the rpm build if we are missing the matching build image.
		imageid=$(docker images -q calico-build/centos${elversion}:latest)
		[ -n "$imageid" ] && ${DOCKER_RUN_RM} -e EL_VERSION=el${elversion} \
		    -e FORCE_VERSION=${FORCE_VERSION} \
		    -e RPM_TAR_ARGS="${RPM_TAR_ARGS}" \
		    $imageid /rpm/build-rpms
	    done

	    cat <<EOF

    +---------------------------------------------------------------------------+
    | RPMs have been built at dist/rpms.                                        |
    +---------------------------------------------------------------------------+

EOF
	    ;;

	* )
	    echo "ERROR: unknown package type \"${package_type}\""
	    exit 255

    esac

done
