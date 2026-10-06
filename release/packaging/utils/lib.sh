#!/bin/bash
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
    if [ -v VERSION ] && git tag -l "${VERSION}" --points-at HEAD| grep -q .; then
        echo "${VERSION}"
        return
    fi
    # Get the last tag, and the number of commits since that tag.
    # Note that we use `git rev-list --count` here, and not `git
    # cherry`, because `git cherry` skips merge commits and so
    # understates the count that `git describe` would report.
    last_tag=$(git_last_tag)
    commits_since=$(git rev-list --count "${last_tag}..HEAD")

    # Generate corresponding PEP 440 version number.
    # Note that PEP 440 only allows [N!]N(.N)*[{a|b|rc}N][.postN][.devN]
    # https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers
    if test "${commits_since}" -eq 0; then
	# There are no commits since the last tag.
	version=${last_tag}
    else
	version=${last_tag}.post${commits_since}
    fi

    echo "${version/-0.dev/rc0}"
}

# Get the current Git commit ID.
function git_commit_id {
    git rev-parse HEAD | cut -c-7
}

function strip_v {
	echo "${1/#v/}"
}

function git_version_to_deb {
    # Our mainline development tags now look like 'v3.31.0-0.dev',
    # but git_auto_version changes them to 'v3.31.0rc.post267'
    # For the Debian package version, translate that to v3.31.0~rc.post267,
    # because it's logically _before_ v3.31.0.
    echo $1 | sed 's/rc/~rc/'
}

function git_version_to_rpm {
    echo $1 | sed 's/\([0-9]\)-\?\(0.dev\)/\1_\2/' | sed 's/\([0-9]\)-python2/\1python2/'
}

# Strip one layer of surrounding single or double quotes from a string.
function strip_quotes {
    local s=$1
    s=${s#\"}; s=${s%\"}
    s=${s#\'}; s=${s%\'}
    echo "${s}"
}

# Print the file exclusions that apply to a Debian source package, one per
# line, in the --exclude form that tar expects.
#
# We need these because we now build the .orig tarball ourselves, instead of
# letting dpkg-source tar up the whole working tree.  Two places declare
# exclusions: the -I options that the caller passes in DPKG_EXCL, and the
# tar-ignore lines in debian/source/options.  dpkg-source hands both of those
# straight to tar, so --exclude means exactly the same thing to us as they
# mean to it.
#
# Must be run with the package's source directory as the working directory.
function deb_tar_excludes {
    local -a opts
    local opt pattern
    local any_pattern=false

    # dpkg-source -I options, as passed to us in DPKG_EXCL.  Use read -a
    # rather than unquoted word splitting, so that patterns containing a
    # wildcard are not expanded against the working directory.
    read -r -a opts <<< "$1"
    for opt in "${opts[@]}"; do
        case "${opt}" in
            -I?*)
                pattern=$(strip_quotes "${opt#-I}")
                printf -- '--exclude=%s\n' "${pattern}"
                any_pattern=true
                ;;
        esac
    done

    # If the caller gave no -I pattern at all -- just a bare "-I", as the
    # networking-calico build does -- dpkg-source would have fallen back to
    # its own built-in ignore list (*.o, .gitignore, .git and so on), so we
    # have to apply that list too or we would start shipping files that the
    # old native tarball left out.  Ask dpkg for the list rather than
    # hardcoding it here, so that it cannot drift.
    if ! ${any_pattern}; then
        perl -MDpkg::Source::Package \
             -e 'printf "--exclude=%s\n", $_
                     for Dpkg::Source::Package::get_default_tar_ignore_pattern();'
    fi

    # tar-ignore lines from debian/source/options.
    if [ -r debian/source/options ]; then
        sed -n 's/^[[:space:]]*tar-ignore[[:space:]]*=[[:space:]]*//p' \
            debian/source/options |
            while read -r pattern; do
                printf -- '--exclude=%s\n' "$(strip_quotes "${pattern}")"
            done
    fi
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

upload_artifact="gcloud --quiet --no-user-output-enabled artifacts yum upload ${GCLOUD_REPO_NAME} --location=us-west1 --project=${GCLOUD_PROJECT:-tigera-wp-tcp-redirect}"
check_artifact="gcloud artifacts files list --repository=${GCLOUD_REPO_NAME} --project=${GCLOUD_PROJECT:-tigera-wp-tcp-redirect} --location=us-west1 --format=json --quiet"
rpmdir=/usr/share/nginx/html/rpm

function ensure_repo_exists {
    reponame=$1
    $ssh_host -- mkdir -p "$rpmdir/$reponame"
}

function copy_rpms_to_host {
    reponame=$1
    rootdir=$(git_repo_root)
    shopt -s nullglob
    for arch in src noarch x86_64; do
        set -- $(find ${rootdir}/release/packaging/output/dist/rpms-el7 -name "*.$arch.rpm")
        if test $# -gt 0; then
            $ssh_host -- mkdir -p $rpmdir/$reponame/$arch/
            $scp_host "$@" ${HOST}:$rpmdir/$reponame/$arch/
        fi
    done
}

function check_rpm_is_uploaded_to_artifact_registry {
    rpmfile=$1
    # Get the package name and version from the RPM file itself,
    # to avoid having to parse filenames. Make sure we get the epoch
    # and release, since those are included in the versions that artifact
    # registry uses. Note that if the epoch is unset GAR treats it as a 0,
    # so if %{EPOCH} is '(none)' we replace it with 0.
    rpmfile_package_name=$(rpm -qp --queryformat "%{NAME}" "${rpmfile}")
    rpmfile_package_version=$(rpm -qp --queryformat "%{EPOCH}:%{VERSION}-%{RELEASE}" "${rpmfile}" | sed -e 's/(none)/0/')

    # Get the list of packages matching the name and version; if this is 0, then we
    # have not uploaded this package+version combo yet. If it's anything else, we have.
    matching_package_count=$(${check_artifact} --package="${rpmfile_package_name}" --version="${rpmfile_package_version}" | jq length)
    if [[ $matching_package_count == 0 ]]; then
        return 1
    else
        return 0
    fi
}

function copy_rpms_to_artifact_registry {
    reponame=$1
    rootdir=$(git_repo_root)
    upload_errors=""
    shopt -s nullglob
    echo "Uploading RPMs to Google Artifact Registry"
    for rpmfile in $(find ${rootdir}/release/packaging/output/dist/rpms-el7 -name "*.rpm" -not -name "*.src.rpm" | sort); do
        filename=$(basename ${rpmfile}) 
        if check_rpm_is_uploaded_to_artifact_registry "${rpmfile}"; then
            echo "  Skipping  ${filename} (already uploaded)"
        else
            echo "  Uploading ${filename}"
            ${upload_artifact} --source="${rpmfile}" || upload_errors="${upload_errors} ${filename}"
        fi
    done

    if [[ ${upload_errors} != "" ]]; then
        echo >&2 "Uploading RPMs complete, but the following files failed to upload to artifact registry:"
        for file in $upload_errors; do
            echo >&2 "  ${file}"
        done
        exit 1
    fi
    echo "Uploading RPMs complete"
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
