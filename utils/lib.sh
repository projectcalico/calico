# Library of functions for Typha process and release automation.

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
    if test ${commits_since} -eq 0; then
	# There are no commits since the last tag.
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
    echo $1 | sed 's/\([0-9]\)-\?\(a\|b\|rc\|pre\)/\1~\2/'
}

# Convert PEP 440 version to RPM.
function git_version_to_rpm {
    echo $1 | sed 's/\([0-9]\)-\?\(a\|b\|rc\|pre\)/\1_\2/'
}

# Check that version is valid.
function validate_version {
    version=$1

    # We allow.
    REGEX="^v[0-9]+\.[0-9]+\.[0-9]+(-?(a|b|rc|pre).*)?$"

    if [[ $version =~ $REGEX ]]; then
	return 0
    else
	return 1
    fi
}

function test_validate_version {

    function expect_valid {
	validate_version $1 || echo $1 wrongly deemed invalid
    }

    function expect_invalid {
	validate_version $1 && echo $1 wrongly deemed valid
    }

    # Test cases.
    expect_valid v1.2.3
    expect_invalid v1.2.3.4
    expect_invalid v.2.3.4
    expect_invalid abc
    expect_invalid v1.2.3.beta
    expect_valid v1.2.3-beta.2
    expect_valid v1.2.3-beta
    expect_valid v1.2.3-alpha
    expect_valid v1.2.3-rc2
    expect_invalid v1:2.3-rc2
    expect_invalid v1.2:3-rc2
    expect_invalid v1.2.3:rc2
}

# Return the series of tags from HEAD back to (but excluding) the
# specified tag, with the most recent tag first.
function git_tags_back_to {

    backstop_tag=$1
    cursor=HEAD
    num_tags=0
    while [ $num_tags -lt 10 ]; do
	previous_tag=`git describe --tags --abbrev=0 $cursor`
	if [ $previous_tag = $backstop_tag ]; then
	    # We've found the last packaged release, so stop.
	    break
	fi
	echo ${previous_tag}
	let 'num_tags += 1'
	cursor="${previous_tag}^"
    done
}
