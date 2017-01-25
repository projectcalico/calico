#!/bin/bash -ex

# Build Debian and RPM packages for the current Git HEAD.
#
# Usage: make-packages.sh [deb] [rpm]

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname $(realpath $0))

# Include function library.
. ${scriptdir}/lib.sh

# Ensure we're in the root of the Git repository.
cd `git_repo_root`

# Get the version based on Git state, and the Git commit ID.
version=${FORCE_VERSION:-`git_auto_version`}
sha=`git_commit_id`

MY_UID=`id -u`
MY_GID=`id -g`
DOCKER_RUN_RM="docker run --rm --user ${MY_UID}:${MY_GID} -v `pwd`:/code"

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

	    # The last Git tag that was packaged, according to the
	    # debian/changelog file.
	    last_pkgd_tag=`awk '/Felix ([^ ]+) \(from Git/{print $3;exit;}' debian/changelog`

	    # We'd like the stanza that we're about to add to include
	    # release notes from all tags since that previous one.
	    tags=`git_tags_back_to ${last_pkgd_tag}`

	    if grep felix debian/changelog | head -n 1 | grep -F "${debver}~__STREAM__"; then
		# debian/changelog already has the version stanza.
		:
	    else
		# Current time in Debian changelog format; e.g. Wed, 02 Mar
		# 2016 14:08:51 +0000.
		timestamp=`date "+%a, %d %b %Y %H:%M:%S %z"`
		mv debian/changelog debian/changelog.prev
		{
		    cat <<EOF
felix (${debver}~__STREAM__) __STREAM__; urgency=low

EOF
		    if ${release}; then
			cat <<EOF
  * Felix ${version} (from Git commit ${sha}).
EOF
			for tag in ${tags}; do
			    echo "    [Changes recorded in $tag tag]"
			    git show ${tag} --format=oneline -s | head -n -1 | tail -n +5 | sed 's/^/    /'
			done
		    else
			cat <<EOF
  * Development snapshot (from Git commit ${sha}).
EOF
		    fi

		    cat <<EOF

 -- Neil Jerram <neil@tigera.io>  ${timestamp}

EOF
		    cat debian/changelog.prev

		} > debian/changelog

		rm debian/changelog.prev
	    fi

	    for series in trusty xenial; do
		${DOCKER_RUN_RM} -e DEB_VERSION=${debver}~${series} \
				 calico-build/${series} debian/build-debs
	    done
	    ;;

	rpm )
	    debver=`git_version_to_rpm ${version}`
	    rpm_spec=rpm/felix.spec

	    # The last Git tag that was packaged, according to the RPM
	    # spec file.
	    last_pkgd_tag=`awk '/Felix ([^ ]+) \(from Git/{print $3;exit;}' rpm/felix.spec`

	    # We'd like the stanza that we're about to add to include
	    # release notes from all tags since that previous one.
	    tags=`git_tags_back_to ${last_pkgd_tag}`

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

	    if grep -F " ${rpmver}-${rpmrel}" ${rpm_spec}; then
		# debian/changelog already has the version stanza.
		:
	    else
		# Add a stanza to the %changelog section.
		timestamp=`date "+%a %b %d %Y"`
		{
		    cat <<EOF
* ${timestamp} Neil Jerram <neil@tigera.io> ${rpmver}-${rpmrel}
EOF
		    if ${release}; then
			cat <<EOF
  - Felix ${version} (from Git commit ${sha}).
EOF
			for tag in ${tags}; do
			    echo "    [Changes recorded in $tag tag]"
			    git show ${tag} --format=oneline -s | head -n -1 | tail -n +5 | sed 's/^/    /'
			done
		    else
			cat <<EOF
  - Development snapshot (from Git commit ${sha}).
EOF
		    fi
		    echo

		} | sed -i '/^%changelog/ r /dev/stdin' ${rpm_spec}
	    fi

	    ${DOCKER_RUN_RM} calico-build/centos7 rpm/build-rpms
	    ;;

	* )
	    echo "ERROR: unknown package type \"${package_type}\""
	    exit -1

    esac

done

cat <<EOF

    +---------------------------------------------------------------------------+
    | Packaging files (debian/changelog and/or rpm/felix.spec) have been        |
    | updated, to build the new packages under dist/.  If you decide to release |
    | those new packages publically (after any QA), please also commit those    |
    | packaging file changes and push to GitHub, so that we have a record of    |
    | how and when the released packages were built.  Otherwise you can discard |
    | those changes.                                                            |
    +---------------------------------------------------------------------------+

EOF
