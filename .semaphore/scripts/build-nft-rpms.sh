#!/bin/bash
set -e
set -o pipefail

# build-nft-rpms.sh: Builds and caches nftables RPMs for a specific architecture.
# This script is intended to be run from Semaphore CI.
# It produces a log file at /tmp/nft-build-${ARCH}.log.

ARCH=$1
if [ -z "$ARCH" ]; then
  echo "Usage: $0 <arch>"
  exit 1
fi
if [ -z "$BUILD_LOG" ]; then
  echo "Error: BUILD_LOG environment variable must be set to the path of the log file."
  exit 1
fi

NFT_RPMS_TAG=$(make --no-print-directory -C hack/rpms/nftables print-tag)
NFT_RPMS_IMAGE="calico/nftables-rpms:${NFT_RPMS_TAG}-${ARCH}"
CACHE_PATH="${GCS_WORKFLOW_DIR}/nft-rpms-${ARCH}.tar.zst"

# Use a subshell to capture all output to the log file while still printing to stdout.
{
  echo "Building nftables RPMs for ${ARCH}..."
  echo "NFT_RPMS_TAG: ${NFT_RPMS_TAG}"
  echo "NFT_RPMS_IMAGE: ${NFT_RPMS_IMAGE}"

  if docker manifest inspect "$NFT_RPMS_IMAGE"; then
    echo "Cache hit for $NFT_RPMS_IMAGE, pulling"
    docker pull "$NFT_RPMS_IMAGE"
  else
    echo "Cache miss for $NFT_RPMS_IMAGE, building"
    docker run --privileged --rm tonistiigi/binfmt --install all
    make -C hack/rpms/nftables image ARCH="$ARCH"

    # SEMAPHORE_GIT_BRANCH is the PR target branch on PR builds (so it
    # equals "master" for every PR landing on master), not the source
    # branch — gate on SEMAPHORE_GIT_PR_NUMBER being empty to detect
    # an actual branch build before pushing.
    if [[ -z "${SEMAPHORE_GIT_PR_NUMBER}" && ( "$SEMAPHORE_GIT_BRANCH" == "master" || "$SEMAPHORE_GIT_BRANCH" == release-* ) ]]; then
      echo "Pushing $NFT_RPMS_IMAGE"
      docker push "$NFT_RPMS_IMAGE"
    fi
  fi

  echo "Saving and uploading image tarball..."
  docker save "$NFT_RPMS_IMAGE" -o /tmp/nft-rpms.tar
  zstd -3 --rm /tmp/nft-rpms.tar
  gcloud storage cp /tmp/nft-rpms.tar.zst "$CACHE_PATH"
} 2>&1 | tee "$BUILD_LOG"
