#!/bin/bash -e

# Generate a unique version for the current Git state.
#
# Usage: gen-version.sh <VERSION_FILE>

version_file=python/version.py

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname $(realpath $0))

# Include function library.
. ${scriptdir}/lib.sh

# Are we in a Git repository?
if git status >/dev/null 2>&1; then

    # Ensure we're in the root of the Git repository.
    cd `git_repo_root`

    # Get the PEP 440 version based on Git state.
    version=`git_auto_version`

    # Write out the version file.
    cat >${version_file} <<EOF
auto_version = "${version}"
EOF

else

    # The version file must already exist!
    test -f ${version_file} || exit 1

    # Touch it to show that this script has run.
    touch ${version_file}

fi

PYTHONPATH=`pwd`/python python -c "import version
print version.auto_version"
