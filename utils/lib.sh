# Library of functions for Felix process and release automation.

# Get the root directory of the Git repository that we are in.
function git_repo_root {
    git rev-parse --show-toplevel
}

# Get the current Git branch.
function git_current_branch {
    git rev-parse --abbrev-ref HEAD
}

# Get the last tag.
function git_last_tag {
    git describe --tags --abbrev=0
}

# Autogenerate PEP 440 version based on current Git state.
function git_auto_version {

    # Get the last tag, and the number of commits since that tag.
    last_tag=`git_last_tag`
    commits_since=`git cherry -v ${last_tag} | wc -l`
    sha=`git_commit_id`
    timestamp=`date -u '+%Y%m%d%H%M%S+0000'`

    # Generate corresponding PEP 440 version number.
    if test ${commits_since} -eq 0 && \
       git diff-index --quiet --cached HEAD && \
       git diff-files --quiet; then
	# There are no commits since the last tag, and no uncommitted changes.
	version=${last_tag}
    else
	version=${last_tag}.post${commits_since}+${timestamp}+${sha}
    fi

    echo $version
}

# Get the current Git commit ID.
function git_commit_id {
    git rev-parse HEAD | cut -c-7
}

# Convert PEP 440 version to Debian.
function git_version_to_deb {
    echo $1 | sed 's/\([0-9]\)-\?\(a\|b\|rc\)/\1~\2/'
}

# Convert PEP 440 version to RPM.
function git_version_to_rpm {
    echo $1 | sed 's/\([0-9]\)-\?\(a\|b\|rc\)/\1_\2/'
}
