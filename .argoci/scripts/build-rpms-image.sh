#!/bin/bash
set -e
set -o pipefail

# build-rpms-image.sh: Builds and caches the hack/rpms/<package> image for a
# specific architecture.

PACKAGE=$1
ARCH=$2
if [ -z "$PACKAGE" ] || [ -z "$ARCH" ]; then
  echo "Usage: $0 <package> <arch>"
  exit 1
fi
if [ -z "$BUILD_LOG" ]; then
  echo "Error: BUILD_LOG environment variable must be set to the path of the log file."
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
S3_CMD="${REPO_ROOT}/.semaphore/s3-cmd"

# shellcheck source=.argoci/scripts/rpms-image-lib.sh
source "${REPO_ROOT}/.argoci/scripts/rpms-image-lib.sh"
RPMS_REPO=$(rpms_image_repo "$PACKAGE")
RPMS_CACHE=$(rpms_image_cache "$PACKAGE")
RPMS_TAG=$(rpms_image_tag "$PACKAGE")
IMAGE="${RPMS_REPO}:${RPMS_TAG}-${ARCH}"
CACHE_NAME="${RPMS_CACHE}-${ARCH}.tar.zst"
CACHE_PATH="${S3_WORKFLOW_DIR}/${CACHE_NAME}"

# Use a subshell to capture all output to the log file while still printing to stdout.
{
  echo "Building the ${PACKAGE} image for ${ARCH}..."
  echo "IMAGE: ${IMAGE}"

  if docker manifest inspect "$IMAGE"; then
    echo "Cache hit for $IMAGE, pulling"
    docker pull "$IMAGE"
  else
    echo "Cache miss for $IMAGE, building"
    docker run --privileged --rm tonistiigi/binfmt --install all
    make -C "${REPO_ROOT}/hack/rpms/${PACKAGE}" image ARCH="$ARCH"
  fi

  echo "Saving and uploading image tarball..."
  docker save "$IMAGE" -o "/tmp/${CACHE_NAME%.zst}"
  zstd -3 --rm "/tmp/${CACHE_NAME%.zst}"
  if [ -n "${CI_ARTIFACT_STORAGE:-}" ]; then
    artifact push workflow "/tmp/${CACHE_NAME}"
  else
    "$S3_CMD" cp "/tmp/${CACHE_NAME}" "$CACHE_PATH"
  fi
} 2>&1 | tee "$BUILD_LOG"
