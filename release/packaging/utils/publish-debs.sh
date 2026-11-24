#!/bin/bash

set -e # Exit immediately on fail
set -u # Fail immediately on undefined variable use
set -o pipefail # Otherwise `cmd | ts` hides cmd's failure

REPO_NAME=${REPO_NAME:-master}
test -n "$SECRET_KEY"

# How many times to try each dput upload; Launchpad's FTP endpoint occasionally
# drops a connection part way through.
UPLOAD_ATTEMPTS=${UPLOAD_ATTEMPTS:-5}

outputdir=$(readlink -f "$(dirname $0)/../output")
rootdir=$(git rev-parse --show-toplevel)
keydir=$(mktemp -t -d calico-publish-debs.XXXXXX)
cp -a "$SECRET_KEY" "${keydir}/key"

# Run dput, retrying on failure.  A retry is safe because dput sends the
# .changes file last, and Launchpad discards an upload session whose .changes
# never arrived; and dput only writes its .ppa.upload log after a complete
# upload, so it won't refuse to retry.
function upload_with_retries {
    local series=$1 package_name=$2 filename=$3
    local attempt delay=${UPLOAD_RETRY_DELAY:-30}
    for attempt in $(seq 1 "${UPLOAD_ATTEMPTS}"); do
        if docker run --rm \
                -v "${rootdir}:/code" \
                -w /code/release/packaging/output \
                calico-build/${series} \
                dput -u "ppa:project-calico/${REPO_NAME}" "${filename}" < /dev/null |
                ts "[upload ${series} ${package_name}]"; then
            return 0
        fi
        if [ "${attempt}" -lt "${UPLOAD_ATTEMPTS}" ]; then
            echo "Upload attempt ${attempt} failed, retrying in ${delay}s" | ts "[upload ${series} ${package_name}]"
            sleep "${delay}"
            delay=$((delay * 2))
        fi
    done
    echo "Upload failed after ${UPLOAD_ATTEMPTS} attempts" | ts "[upload ${series} ${package_name}]"
    return 1
}

for series in focal jammy noble; do
    echo
    echo "Processing uploads for ${series}"
    # Get the packages and versions that already exist in the PPA, so we can avoid
    # uploading the same package and version as already exist.  (As they would be rejected
    # anyway by Launchpad.)  If this lookup fails, we just attempt all the uploads, and
    # Launchpad rejects the duplicates.
    sources_url="https://ppa.launchpadcontent.net/project-calico/${REPO_NAME}/ubuntu/dists/${series}/main/source/Sources.gz"
    if curl -fs -I --retry 3 "${sources_url}" > /dev/null; then
        if existing_packages=$(curl -fsSL --retry 3 "${sources_url}" | zcat | awk '/^Package:/{printf("%s_", $2);} /^Version:/{sub(/^[0-9]:/,"", $2); print $2;}'); then
            mapfile -t existing_packages <<< "${existing_packages}"
            for existing_package in "${existing_packages[@]}"; do
                # echo "Launchpad has sources for ${existing_package} already, marking to skip" | ts "[check ${series} ${existing_package}]"
                touch "${outputdir}/${existing_package}_source.ppa.previously-uploaded"
            done
        else
            echo "Failed to read ${sources_url}; will attempt all uploads for ${series}"
        fi
    fi

    # Loop through our `changes` files, one each for each source package we're uploading
    # sign them, and then upload the file via dput.
    #
    # Another modernization that we probably don't need - use `find` to list files, delimit on nulls,
    # have bash read each entry null-delimited (-d), with escaped backslashes (-r), into $changes_file
    # so that we don't have to worry about spaces in filenames destroying our script.
    #
    # The `find` output is fed in by process substitution, rather than by piping into
    # `while`, so that the loop body runs in this shell and a failure exits the script.
    #
    # Relevant filenames look like this:
    #
    #   <packagename>_<version>-<ubuntu_release>_source.changes
    #       The changes file; we pass this to `dput` so it knows what to upload
    #
    #   <packagename>_<version>-<ubuntu_release>_source.ppa.upload
    #       The .ppa.upload file is created by `dput` when we successfully complete an upload
    #
    #   <packagename>_<version>-<ubuntu_release>_source.ppa.previously-uploaded
    #       The .ppa.previously-uploaded file is created by us if launchpad already has this
    #       file. Emulates the function of the above file for our purposes, but lets us
    #       distingush between "we just completed this upload" vs "we uploaded this at
    #       some point previously"
    #
    while read -r -d $'\0' changes_file; do
        filename=$(basename "${changes_file}")
        package_name="${filename%%_*}"
        base_ppa_file_path="$(basename "${changes_file}" .changes).ppa"
        if test -f "${outputdir}/${base_ppa_file_path}.upload"; then
            echo "Upload was already completed, skipping" | ts "[upload ${series} ${package_name}]"
        elif test -f "${outputdir}/${base_ppa_file_path}.previously-uploaded"; then
            echo "Launchpad already has this source package, skipping" | ts "[upload ${series} ${package_name}]"
        else
            # Ensure we sign our source packages
            docker run --rm \
                -v "${rootdir}:/code" \
                -v "${keydir}:/keydir" \
                -w /code/release/packaging/output calico-build/${series} \
                /bin/sh -c "gpg --quiet --import --batch /keydir/key && debsign -k'*@' --no-re-sign ${filename}" < /dev/null |
                ts "[sign ${series} ${package_name}]"

            upload_with_retries "${series}" "${package_name}" "${filename}"
        fi
    done < <(find "${outputdir}" -name "*-${series}_source.changes" -print0)
done

