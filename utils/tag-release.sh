#!/bin/bash -e

# Create an annotated tag for a new release.
#
# Usage: tag-release.sh [<NEW-VERSION>]

nextrel=$1

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname $(readlink -f $0))

# Include function library.
. ${scriptdir}/lib.sh

# Validate the specified new version.
validate_version $nextrel || {
    echo "Version $nextrel is not valid."
    echo "See 'validate_version' in ${scriptdir}/lib.sh for guidance."
    exit 1
}

# Ensure we're in the root of the Git repository.
cd `git_repo_root`

# Generate raw material for release notes as the list of changes - from Git
# commit messages - since the last release.
last_tag=`git_last_tag`
release_notes=`mktemp -t felix-release-notes.XXXXXXXXXX`
git cherry -v $last_tag | cut '-d ' -f 3- | sed 's/^/- /' > $release_notes

# Open the release notes file in $EDITOR and ask the user to edit it into a
# more appropriate form.
cat <<EOF

Changes (i.e. Git commit messages) since the last release ($last_tag) have been
written into $release_notes.

Hit Return for that file to be popped up.  (Assuming that \$EDITOR is usefully
set on your machine.  If not, hit Return and then open the file yourself.)
Then review and edit that (as necessary) so as to provide a good set of release
notes for our partners and customers, saying what is new or changed in this
release.

EOF
read

$EDITOR $release_notes

cat <<EOF

Edited release notes are:

EOF
cat $release_notes

cat <<EOF

Hit Return to confirm that these are good to release.  (Otherwise edit the file
some more until they are good, and then hit Return.)

EOF
read

# Create annotated release tag.
git tag $nextrel -F $release_notes
