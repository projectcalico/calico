#!/bin/bash
set -e
set -o pipefail

# push-nft-rpms.sh: Publishes a cached nftables RPM image for a specific
# architecture. This script is intended to be run only from trusted
# Semaphore branch builds after build-nft-rpms.sh has uploaded the image tarball
# to GCS.

ARCH=$1
if [ -z "$ARCH" ]; then
  echo "Usage: $0 <arch>"
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

NFT_RPMS_TAG=$(make --no-print-directory -C hack/rpms/nftables print-tag)
NFT_RPMS_IMAGE="calico/nftables-rpms:${NFT_RPMS_TAG}-${ARCH}"
CACHE_PATH="${GCS_WORKFLOW_DIR}/nft-rpms-${ARCH}.tar.zst"

{
  echo "Publishing nftables RPMs for ${ARCH}..."
  echo "NFT_RPMS_TAG: ${NFT_RPMS_TAG}"
  echo "NFT_RPMS_IMAGE: ${NFT_RPMS_IMAGE}"

  if docker manifest inspect "$NFT_RPMS_IMAGE" >/dev/null 2>&1; then
    echo "Image already published, skipping push"
  else
    echo "$DOCKER_TOKEN" | docker login --username "$DOCKER_USER" --password-stdin
    gcloud storage cp "$CACHE_PATH" /tmp/nft-rpms.tar.zst
    zstd -d --rm /tmp/nft-rpms.tar.zst
    docker load -i /tmp/nft-rpms.tar
    rm -f /tmp/nft-rpms.tar
    docker push "$NFT_RPMS_IMAGE"
  fi
} 2>&1 | tee "$BUILD_LOG"
