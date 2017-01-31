#!/bin/bash -e

# Create an annotated tag for a new release.
#
# Usage: tag-release.sh [<NEW-VERSION>]

nextrel=$1

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname $(realpath $0))

# Include function library.
. ${scriptdir}/lib.sh

# Validate the specified new version.
validate_version ${nextrel} || {
    echo "Version ${nextrel} is not valid."
    echo "See 'validate_version' in ${scriptdir}/lib.sh for guidance."
    exit 1
}

# Ensure we're in the root of the Git repository.
cd `git_repo_root`

# Generate raw material for release notes as the list of changes - from Git
# commit messages - since the last release.
last_tag=`git_last_tag`
release_notes=./release-notes-${nextrel}
echo "Felix version ${nextrel}" > ${release_notes}
echo >> ${release_notes}

git cherry -v $last_tag | cut '-d ' -f 3- | sed 's/^/- /' >> ${release_notes}

# Ask user to edit the relase note to their liking.
cat <<EOF

Changes (i.e. Git commit messages) since the last release ($last_tag) have been
written into ${release_notes}.  These will become the tag release note.

Please examine that file and edit as appropriate.

Once you have edited the file to your liking, run

  make continue-release VERSION=${nextrel}

to create the tag and finish off the release.

EOF
