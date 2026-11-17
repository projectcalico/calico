#!/bin/bash
set -e
set -o pipefail

# push-rpms-image.sh: Publishes the hack/rpms/<package> image that
# build-rpms-image.sh cached: each architecture, then the multi-arch manifest
# that names them. Trusted branch builds only.

PACKAGE=$1
if [ -z "$PACKAGE" ]; then
  echo "Usage: $0 <package>"
  exit 1
fi
if [ -z "$BUILD_LOG" ]; then
  echo "Error: BUILD_LOG environment variable must be set to the path of the log file."
  exit 1
fi
if [ -z "$DOCKER_USER" ] || [ -z "$DOCKER_TOKEN" ]; then
  echo "Error: DOCKER_USER and DOCKER_TOKEN must be set."
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
S3_CMD="${REPO_ROOT}/.semaphore/s3-cmd"

source "${REPO_ROOT}/.argoci/scripts/rpms-image-lib.sh"
rpms_image_vars "$PACKAGE"
MANIFEST="${RPMS_REPO}:${RPMS_TAG}"

push_arch() {
  local arch=$1
  local image="${MANIFEST}-${arch}"
  local cache_name="${RPMS_CACHE}-${arch}.tar.zst"

  if docker manifest inspect "$image" >/dev/null 2>&1; then
    echo "${image} already published, skipping push"
    return
  fi
  if [ -n "${CI_ARTIFACT_STORAGE:-}" ]; then
    ( cd /tmp && artifact pull workflow "${cache_name}" )
  else
    "$S3_CMD" cp "${S3_WORKFLOW_DIR}/${cache_name}" "/tmp/${cache_name}"
  fi
  zstd -d --rm "/tmp/${cache_name}"
  docker load -i "/tmp/${cache_name%.zst}"
  rm -f "/tmp/${cache_name%.zst}"
  docker push "$image"
  # Four of these would not fit on a small runner's disk.
  docker rmi "$image" >/dev/null
}

{
  echo "Publishing the ${PACKAGE} image..."
  echo "MANIFEST: ${MANIFEST}"

  if docker manifest inspect "$MANIFEST" >/dev/null 2>&1; then
    echo "Manifest already published, so every architecture is too; nothing to push"
  else
    echo "$DOCKER_TOKEN" | docker login --username "$DOCKER_USER" --password-stdin
    images=()
    for arch in $RPMS_ARCHES; do
      push_arch "$arch"
      images+=("${MANIFEST}-${arch}")
    done
    docker manifest create "$MANIFEST" "${images[@]}"
    docker manifest push --purge "$MANIFEST"
  fi
} 2>&1 | tee "$BUILD_LOG"
