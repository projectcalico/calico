#!/bin/bash

set -e # Exit immediately on fail
set -u # Fail immediately on undefined variable use

REPO_NAME=${REPO_NAME:-master}
test -n "$SECRET_KEY"

outputdir=$(readlink -f "$(dirname $0)/../output")
rootdir=$(git rev-parse --show-toplevel)
keydir=$(mktemp -t -d calico-publish-debs.XXXXXX)
cp -a "$SECRET_KEY" "${keydir}/key"

# Sign all source packages.
if [ -t 0 ]; then
    # STDIN is a terminal, so whoever is running this code can provide a pass phrase for
    # their GPG key.  Pass STDIN through to the Docker container, to enable that.
    interactive=-ti
else
    # STDIN is not a terminal - probably we're running in our CI system.  We mustn't pass
    # -ti to docker-run, and $SECRET_KEY must not require a pass phrase.
    interactive=
fi

for series in focal jammy noble; do
    echo "Processing uploads for ${series}"
    echo
    # Get the packages and versions that already exist in the PPA, so we can avoid
    # uploading the same package and version as already exist.  (As they would be rejected
    # anyway by Launchpad.)
    sources_url="https://ppa.launchpadcontent.net/project-calico/${REPO_NAME}/ubuntu/dists/${series}/main/source/Sources.gz"
    if curl -fs -I "${sources_url}" > /dev/null; then
        existing_packages=$(curl -fsSL "${sources_url}" | zcat | awk '/^Package:/{printf("%s_", $2);} /^Version:/{sub(/^[0-9]:/,"", $2); print $2;}')
        mapfile -t existing_packages <<< "${existing_packages}"
        for existing_package in "${existing_packages[@]}"; do
            # echo "Launchpad has sources for ${existing_package} already, marking to skip" | ts "[check ${series} ${existing_package}]"
            touch "${outputdir}/${existing_package}_source.ppa.previously-uploaded"
        done
    fi

    # Loop through our `changes` files, one each for each source package we're uploading
    # sign them, and then upload the file via dput.
    #
    # Another modernization that we probably don't need - use `find` to list files, delimit on nulls,
    # have bash read each entry null-delimited (-d), with escaped backslashes (-r), into $changes_file
    # so that we don't have to worry about spaces in filenames destroying our script.
    find "${outputdir}" -name "*-${series}_source.changes" -print0 | while read -r -d $'\0' changes_file; do
        filename=$(basename "${changes_file}")
        package_name="${filename%%_*}"
        if test -f "${outputdir}/${existing_package}_source.ppa.upload"; then
            echo "Upload was already completed, skipping" | ts "[upload ${series} ${package_name}]"
        elif test -f "${outputdir}/${existing_package}_source.ppa.previously-uploaded"; then
            echo "Launchpad already has this source package, skipping" | ts "[upload ${series} ${package_name}]"
        else
            # Ensure we sign our source packages
            docker run --rm ${interactive} \
                -v "${rootdir}:/code" \
                -v "${keydir}:/keydir" \
                -w /code/release/packaging/output calico-build/${series} \
                /bin/sh -c "gpg --quiet --import --batch < /keydir/key && debsign -k'*@' --no-re-sign ${filename}" | ts  "[sign ${series} ${package_name}]"

            # Upload the packages to Launchpad via dput
            docker run --rm \
                -v "${rootdir}:/code" \
                -w /code/release/packaging/output \
                calico-build/${series} \
                dput -u "ppa:project-calico/${REPO_NAME}" "${filename}" | ts "[upload ${series} ${package_name}]"
        fi
    done
done
