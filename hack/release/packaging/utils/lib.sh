# Library of functions for Calico process and release automation.

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

    # If VERSION is defined and there is a tag here (at HEAD) that
    # matches VERSION, ensure that we use that tag even if there are
    # other tags on the same commit.
    if [ "${VERSION}" -a "`git tag -l $VERSION --points-at HEAD`" = $VERSION ]; then
	echo ${VERSION}
	return
    fi

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

function strip_v {
	echo $1 | sed 's/^v//'
}

function git_version_to_deb {
    # Our mainline development tags now look like 'v3.14.0-0.dev'.
    # For the Debian package version, translate that to v3.14.0~0.dev,
    # because it's logically _before_ v3.14.0.
    echo $1 | sed 's/\([0-9]\)-0.dev/\1~0.dev/'
}

function git_version_to_rpm {
    echo $1 | sed 's/\([0-9]\)-\?\(0.dev\)/\1_\2/' | sed 's/\([0-9]\)-python2/\1python2/'
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
    expect_invalid 1.2.3.4
    expect_invalid .2.3.4
    expect_invalid abc
    expect_invalid 1.2.3.beta
    expect_valid v1.2.3-beta.2
    expect_valid v1.2.3-beta
    expect_valid v1.2.3-alpha
    expect_valid v1.2.3-rc2
    expect_invalid 1:2.3-rc2
    expect_invalid 1.2:3-rc2
    expect_invalid 1.2.3:rc2

    # All Felix tags since 1.0.0 (with v prefixed):
    expect_valid v1.0.0
    expect_valid v1.1.0
    expect_valid v1.2.0
    expect_valid v1.2.0-pre2
    expect_valid v1.2.1
    expect_valid v1.2.2
    expect_valid v1.3.0
    expect_valid v1.3.0-pre5
    expect_valid v1.3.0a5
    expect_valid v1.3.0a6
    expect_valid v1.3.1
    expect_valid v1.4.0
    expect_valid v1.4.0b1
    expect_valid v1.4.0b2
    expect_valid v1.4.0b3
    expect_valid v1.4.1b1
    expect_valid v1.4.1b2
    expect_valid v1.4.2
    expect_valid v1.4.3
    expect_valid v1.4.4
    expect_valid v2.0.0-beta
    expect_valid v2.0.0-beta-rc2
    expect_valid v2.0.0-beta.2
    expect_valid v2.0.0-beta.3
    expect_valid v2.0.0-beta-rc1
}

# Setup for accessing the RPM host.  Requires GCLOUD_ARGS and HOST to
# be set by the caller.
ssh_host="gcloud --quiet compute ssh ${GCLOUD_ARGS} ${HOST}"
scp_host="gcloud --quiet compute scp ${GCLOUD_ARGS}"
rpmdir=/usr/share/nginx/html/rpm

function ensure_repo_exists {
    reponame=$1
    $ssh_host -- mkdir -p $rpmdir/$reponame
}

function copy_rpms_to_host {
    reponame=$1
    rootdir=`git_repo_root`
    shopt -s nullglob
    for arch in src noarch x86_64; do
	set -- `find ${rootdir}/hack/release/packaging/output/dist/rpms-el7 -name "*.$arch.rpm"`
	if test $# -gt 0; then
	    $ssh_host -- mkdir -p $rpmdir/$reponame/$arch/
	    $scp_host "$@" ${HOST}:$rpmdir/$reponame/$arch/
	fi
    done
}

# Clean and update repository metadata.  This includes ensuring that
# all RPMs are signed with the Project Calico Maintainers secret key,
# and that the public key is downloadable so that installers can
# verify RPM signatures.
#
# Note, the </dev/null is critical on the RPM signing line; otherwise
# that command consumes the rest of the here doc when trying to read a
# pass phrase from stdin.  No pass phrase is actually needed, because
# our key doesn't have one.
function update_repo_metadata {
    reponame=$1
    $ssh_host <<EOF
set -x
rm -f \`repomanage --old $rpmdir/$reponame\`
rpm --define '_gpg_name Project Calico Maintainers' --resign $rpmdir/$reponame/*/*.rpm </dev/null
gpg --export -a "Project Calico Maintainers" > $rpmdir/$reponame/key
createrepo $rpmdir/$reponame
EOF
}
