#!/bin/bash -xe

# Automatically update the codebase for a new release, and (locally) commit
# those changes.
#
# Usage: create-release-commit.sh [<NEW-VERSION>]
#
# If <NEW-VERSION> isn't specified on the command line, we prompt for it.

nextrel=$1
if test -z "${nextrel}"; then
    echo -n "New version: "
    read nextrel
fi

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname $(readlink -f $0))

# Include function library.
. ${scriptdir}/lib.sh

# Ensure we're in the root of the Git repository.
cd `git_repo_root`

# Add the new version header and list of changes - from Git commit messages -
# to CHANGES.md.
last_tag=`git describe --tags --abbrev=0`
{
    echo '##' ${nextrel}
    echo
    git cherry -v $last_tag | cut '-d ' -f 3- | sed 's/^/- /'
    echo

} | sed -i '2r /dev/stdin' CHANGES.md

# Pause to allow the user to edit that list of changes into a more
# consumer-friendly form.
cat <<EOF

Please review CHANGES.md to check that the new version number is correct and to
improve - if necessary - the description for our partners and customers of what
is new or changed in this release.

When you're happy that the content of CHANGES.md is good, hit Return to
continue with propagating the new version and list of changes to all the other
places that they need to be...

EOF
read

# Read the new version back again from CHANGES.md - in case the user changed
# it.
nextrel=`grep '##' CHANGES.md | head -1 | awk '{print $2;}'`

# Set the source package name.  (Some library functions need this.)
package=felix

# Update the Debian changelog.
series=__STREAM__ update_debian_changelog

# Update the RPM spec.
update_rpm_spec

# Update version setting (if present) in setup.py.
sed -i "s/^    version=.*$/    version=\"${nextrel#*:}\",/" python/setup.py

# Git commit release changes so far.
git commit -a -m "Version ${nextrel#*:}"
