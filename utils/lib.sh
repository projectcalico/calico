# Library of functions for Calico process and release automation.

# Get the root directory of the Git repository that we are in.
function git_repo_root {
    git rev-parse --show-toplevel
}

# Update the RPM spec file for the release.  Environment required: ${package},
# ${nextrel}.
function update_rpm_spec {

    origd=`pwd`
    cd `git_repo_root`/rpm

    rpm_spec=${package}.spec

    # Generate RPM version and release.
    IFS=- read version qualifier <<< ${nextrel}
    if test "${qualifier}"; then
	rpmver=${version}
	rpmrel=0.1.${qualifier}
    else
	rpmver=${version}
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
  - ${package} version ${rpmver#*:}-${rpmrel} release
EOF
	set - `grep '##' ../CHANGES.md`
	this_ver=$2
	last_ver=$4
	sed -n "/^## ${this_ver}$/,/^## ${last_ver}$/p" ../CHANGES.md | head -n -2 | tail -n +3 | sed 's/^/    /'
	echo
    } | sed -i '/^%changelog/ r /dev/stdin' ${rpm_spec}

    cd ${origd}
}

# Update the Debian changelog for the release.  Environment required:
# ${package}, ${nextrel}, ${series}.
function update_debian_changelog {

    origd=`pwd`
    cd `git_repo_root`/debian

    # If the first changelog entry includes __SNAPSHOT__, delete it.
    if sed '/^ -- / q' changelog | grep __SNAPSHOT__; then
	sed -i '1,/ --/d' changelog
	sed -i '1d' changelog
    fi

    mv changelog changelog.committed

    # Get the current Git commit ID.
    sha=`git rev-parse HEAD | cut -c-7`

    # Current time in Debian changelog format; e.g. Wed, 02 Mar 2016 14:08:51
    # +0000.
    timestamp=`date "+%a, %d %b %Y %H:%M:%S %z"`

    # Generate Debian version.  If the version number has a -part, convert it
    # to ~part for Debian.
    IFS=- read version qualifier <<< ${nextrel}
    if test "${qualifier}"; then
	debver=${version}~${qualifier}
    else
	debver=${version}
    fi

    {
	cat <<EOF
${package} (${debver}-${series}) ${series}; urgency=low

EOF
	cat <<EOF
  * ${package} release (from Git commit ${sha}).
EOF
	set - `grep '##' ../CHANGES.md`
	this_ver=$2
	last_ver=$4
	sed -n "/^## ${this_ver}$/,/^## ${last_ver}$/p" ../CHANGES.md | head -n -2 | tail -n +3 | sed 's/^/    /'

	cat <<EOF

 -- Neil Jerram <neil@tigera.io>  ${timestamp}

EOF
	cat changelog.committed

    } > changelog

    rm changelog.committed

    cd ${origd}
}
