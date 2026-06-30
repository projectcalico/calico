#!/bin/bash
set -e
set -o pipefail

# build-bird-image.sh: Builds and caches the upstream calico/bird image for a
# specific architecture. Intended to be run from Semaphore CI. Mirrors
# build-nft-rpms.sh. Produces a log at $BUILD_LOG.

ARCH=$1
if [ -z "$ARCH" ]; then
  echo "Usage: $0 <arch>"
  exit 1
fi
if [ -z "$BUILD_LOG" ]; then
  echo "Error: BUILD_LOG environment variable must be set to the path of the log file."
  exit 1
fi

# Per-arch tag (consumed by node/Dockerfile FROM) and the plain alias (used as a
# runnable BGP test peer by e2e/k8st/kubevirt).
BIRD_IMAGE=$(make --no-print-directory -C bird print-image ARCH="${ARCH}")
BIRD_IMAGE_PLAIN="${BIRD_IMAGE%-${ARCH}}"
CACHE_PATH="${GCS_WORKFLOW_DIR}/bird-image-${ARCH}.tar.zst"

{
  echo "Building calico/bird for ${ARCH}..."
  echo "BIRD_IMAGE: ${BIRD_IMAGE}"
  echo "BIRD_IMAGE_PLAIN: ${BIRD_IMAGE_PLAIN}"

  if docker manifest inspect "$BIRD_IMAGE"; then
    echo "Cache hit for $BIRD_IMAGE, pulling"
    docker pull "$BIRD_IMAGE"
    docker tag "$BIRD_IMAGE" "$BIRD_IMAGE_PLAIN"
  else
    echo "Cache miss for $BIRD_IMAGE, building"
    docker run --privileged --rm tonistiigi/binfmt --install all
    make -C bird image ARCH="$ARCH"
  fi

  echo "Saving and uploading image tarball (both tags)..."
  docker save "$BIRD_IMAGE" "$BIRD_IMAGE_PLAIN" -o /tmp/bird-image.tar
  zstd -3 --rm /tmp/bird-image.tar
  gcloud storage cp /tmp/bird-image.tar.zst "$CACHE_PATH"
} 2>&1 | tee "$BUILD_LOG"
