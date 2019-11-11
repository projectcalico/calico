#!/bin/bash -ex

# Build Debian and RPM packages for the current Git HEAD.
#
# Usage: make-packages.sh [deb] [rpm]

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname $(realpath $0))

# Include function library.
. ${scriptdir}/lib.sh

# Get the version based on Git state, and the Git commit ID.
version=${FORCE_VERSION:-`git_auto_version`}
sha=`git_commit_id`

MY_UID=`id -u`
MY_GID=`id -g`
DOCKER_RUN_RM="docker run --rm --user ${MY_UID}:${MY_GID} -v $(dirname `pwd`):/code -w /code/$(basename `pwd`)"

# Determine if this is a release (i.e. corresponds exactly to a Git tag) or a
# snapshot.
release=true
case ${version} in
    *.post* )
	release=false
	;;
esac

# Build the requested package types.
for package_type in "$@"; do

    case ${package_type} in

	deb )
	    # The Debian version that we are about to generate.
	    debver=`git_version_to_deb ${version}`
	    debver=`strip_v ${debver}`

	    # Current time in Debian changelog format; e.g. Wed, 02
	    # Mar 2016 14:08:51 +0000.
	    timestamp=`date "+%a, %d %b %Y %H:%M:%S %z"`
	    for series in trusty xenial bionic; do
		{
		    cat <<EOF
${PKG_NAME} (${DEB_EPOCH}${debver}~$series) $series; urgency=low

EOF
		    if ${release}; then
			cat <<EOF
  * ${NAME} ${version} (from Git commit ${sha}).
EOF
		    else
			cat <<EOF
  * Development snapshot (from Git commit ${sha}).
EOF
		    fi

		    cat <<EOF

 -- Neil Jerram <neil@tigera.io>  ${timestamp}

EOF
		} > debian/changelog

		if [ ${PKG_NAME} = networking-calico ]; then
		    if [ "$FORCE_VERSION" ]; then
			# When FORCE_VERSION is specified, that is also the PBR version
			# that we should set.  Note: this is relevant in particular when
			# there are multiple version tags on the same networking-calico
			# commit (which is quite common as networking-calico doesn't
			# change much).  The alternative, automated method, just below,
			# is currently broken when there are multiple tags on the same
			# commit; see https://bugs.launchpad.net/pbr/+bug/1453996.
			pbr_version=$FORCE_VERSION
		    else
			pbr_version=`${DOCKER_RUN_RM} -i calico-build/${series} python - <<'EOF'
import pbr.version
print pbr.version.VersionInfo('networking-calico').release_string()
EOF`
		    fi
		    # Update PBR_VERSION setting in debian/rules.
		    sed -i "s/^export PBR_VERSION=.*$/export PBR_VERSION=${pbr_version}/" debian/rules
		fi

		${DOCKER_RUN_RM} calico-build/${series} dpkg-buildpackage -I -S
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
		debver=`git_version_to_rpm ${version}`
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
  - ${NAME} ${version} (from Git commit ${sha}).
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
	    if [ ${PKG_NAME} = felix ]; then
		elversions="7 6"
	    fi
	    for elversion in ${elversions}; do
		# Skip the rpm build if we are missing the matching build image.
		imageid=$(docker images -q calico-build/centos${elversion}:latest)
		[ -n "$imageid"  ] && ${DOCKER_RUN_RM} -e EL_VERSION=el${elversion} \
		    -e FORCE_VERSION=${FORCE_VERSION} \
		    $imageid ../rpm/build-rpms
	    done

	    cat <<EOF

    +---------------------------------------------------------------------------+
    | RPMs have been built at dist/rpms.                                        |
    +---------------------------------------------------------------------------+

EOF
	    ;;

	* )
	    echo "ERROR: unknown package type \"${package_type}\""
	    exit -1

    esac

done
