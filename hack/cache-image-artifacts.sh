#!/bin/bash

# Cache build artifacts (not just docker images) to GCS so downstream
# component jobs don't have to rebuild them.
#
# The docker image alone isn't enough: Make prereqs like the Go binary,
# LICENSE, and any generated files under the repo are still missing after a
# `docker load`, so targets that depend on them rebuild the image.
#
# Strategy: stamp the filesystem before the build, tar every file newer than
# the stamp (preserving mtimes) after the build, and upload both the tar and
# the docker image to GCS. On load, extract the tar back into the repo root
# and docker-load the image. No paths are hardcoded, so this stays correct
# across dependency changes.
#
# Usage:
#   cache-image-artifacts.sh pre-build
#   cache-image-artifacts.sh store <name> <image-ref>
#   cache-image-artifacts.sh load  <name>

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
STAMP=/tmp/.cache-artifacts-stamp

pre_build() {
    touch "$STAMP"
}

store() {
    local name=$1
    local image_ref=$2

    if [ ! -f "$STAMP" ]; then
        echo "ERROR: $STAMP missing; run 'pre-build' before the build." >&2
        exit 1
    fi

    local artifacts_tar="/tmp/${name}-artifacts.tar.zst"
    local image_tar="/tmp/${name}-image.tar.zst"

    echo "Capturing artifacts newer than stamp..."
    # Collect the list separately so find exit status is visible and so the
    # file count is logged. Prune noisy/never-useful paths to keep the tar
    # small.
    local list
    list=$(mktemp)
    (
        cd "$REPO_ROOT"
        find . -newer "$STAMP" -type f \
            -not -path './.git/*' \
            -not -path './.semaphore/*' \
            -print0 > "$list"
    )
    local count
    count=$(tr -cd '\0' < "$list" | wc -c)
    echo "Archiving $count file(s) into $artifacts_tar"

    tar --null -T "$list" --use-compress-program="zstd -3" \
        -cf "$artifacts_tar" -C "$REPO_ROOT" .
    rm -f "$list"

    echo "Saving docker image $image_ref to $image_tar"
    docker save "$image_ref" | zstd -3 -o "$image_tar"

    echo "Uploading to ${GCS_WORKFLOW_DIR}/"
    gcloud storage cp "$artifacts_tar" "$image_tar" "${GCS_WORKFLOW_DIR}/"
    rm -f "$artifacts_tar" "$image_tar"
}

load() {
    local name=$1
    local artifacts_tar="/tmp/${name}-artifacts.tar.zst"
    local image_tar="/tmp/${name}-image.tar.zst"

    if ! gcloud storage cp "${GCS_WORKFLOW_DIR}/${name}-image.tar.zst" "$image_tar" 2>/dev/null; then
        echo "No cached ${name} image found, downstream jobs will build from source."
        return 0
    fi

    echo "Loading cached ${name} docker image..."
    zstd -dc "$image_tar" | docker load
    rm -f "$image_tar"

    if gcloud storage cp "${GCS_WORKFLOW_DIR}/${name}-artifacts.tar.zst" "$artifacts_tar" 2>/dev/null; then
        echo "Extracting cached ${name} build artifacts into repo..."
        # Extract with -m so every artifact gets an mtime of "now" instead of
        # its archived mtime. The working-copy cache and the global git
        # checkout both reset source file mtimes in downstream jobs; if we
        # preserved the archive mtimes, Make would see those sources as
        # newer than the cached binaries and markers and rebuild. Stamping
        # all artifacts as the freshest files in the tree matches the prior
        # touch-marker behaviour but covers every cached file.
        tar --use-compress-program="zstd -d" -xmf "$artifacts_tar" -C "$REPO_ROOT"
        rm -f "$artifacts_tar"
    else
        echo "No cached ${name} artifacts tar found (image only)."
    fi
}

cmd=${1:-}
shift || true
case "$cmd" in
    pre-build) pre_build ;;
    store)     store "$@" ;;
    load)      load  "$@" ;;
    *)
        echo "Usage: $0 {pre-build|store <name> <image-ref>|load <name>}" >&2
        exit 2
        ;;
esac
