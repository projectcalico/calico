#!/bin/bash
set -e
set -o pipefail

# load-rpms-image.sh: Makes the hack/rpms/<package> image available locally,
# so a build that names it resolves without a mid-build pull.
#
# The Docker Hub fallback is safe: the tag is a hash of the recipe, so a
# published image holds exactly this content.

PACKAGE=$1
ARCH=$2
if [ -z "$PACKAGE" ] || [ -z "$ARCH" ]; then
  echo "Usage: $0 <package> <arch>"
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

fetch_tarball() {
  if [ -n "${CI_ARTIFACT_STORAGE:-}" ]; then
    ( cd /tmp && artifact pull workflow "${CACHE_NAME}" )
    return
  fi
  "$S3_CMD" cp "$CACHE_PATH" "/tmp/${CACHE_NAME}"
}

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "${IMAGE} is already present locally"
  exit 0
fi

if fetch_tarball; then
  echo "Loading ${IMAGE} from the workflow cache"
  zstd -d --rm "/tmp/${CACHE_NAME}"
  docker load -i "/tmp/${CACHE_NAME%.zst}"
  rm -f "/tmp/${CACHE_NAME%.zst}"
  exit 0
fi

echo "No cached tarball; pulling ${IMAGE} from Docker Hub instead"
if ! docker pull "$IMAGE"; then
  echo "ERROR: ${IMAGE} is in neither the workflow cache nor Docker Hub." >&2
  echo "Only a tag that has already been published can be consumed without a" >&2
  echo "producer run, and this one has not been." >&2
  exit 1
fi
