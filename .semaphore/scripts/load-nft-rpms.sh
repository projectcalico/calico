#!/bin/bash
set -e
set -o pipefail

# load-nft-rpms.sh: Makes the patched nftables RPMs producer image available
# locally, so a consumer Dockerfile's `FROM ${NFT_RPMS_IMAGE}` resolves without
# reaching out mid-build. Run by every block that lists "Build: nftables RPMs"
# in its dependencies.
#
# The image normally arrives as a tarball in the workflow's S3 area, put there
# by build-nft-rpms.sh. A build without S3 credentials runs read-only (see
# .semaphore/s3-cmd), so that upload never happened; fall back to pulling the
# published image from Docker Hub, which is where build-nft-rpms.sh itself got
# it on a cache hit. The same fallback covers a skipped producer block.

ARCH=$1
if [ -z "$ARCH" ]; then
  echo "Usage: $0 <arch>"
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
S3_CMD="${REPO_ROOT}/.semaphore/s3-cmd"

NFT_RPMS_TAG=$(make --no-print-directory -C "${REPO_ROOT}/hack/rpms/nftables" print-tag)
NFT_RPMS_IMAGE="calico/nftables-rpms:${NFT_RPMS_TAG}-${ARCH}"
CACHE_PATH="${S3_WORKFLOW_DIR}/nft-rpms-${ARCH}.tar.zst"

if docker image inspect "$NFT_RPMS_IMAGE" >/dev/null 2>&1; then
  echo "${NFT_RPMS_IMAGE} is already present locally"
  exit 0
fi

if "$S3_CMD" cp "$CACHE_PATH" /tmp/nft-rpms.tar.zst; then
  echo "Loading ${NFT_RPMS_IMAGE} from ${CACHE_PATH}"
  zstd -d --rm /tmp/nft-rpms.tar.zst
  docker load -i /tmp/nft-rpms.tar
  rm -f /tmp/nft-rpms.tar
  exit 0
fi

echo "No tarball at ${CACHE_PATH}; pulling ${NFT_RPMS_IMAGE} from Docker Hub instead"
if ! docker pull "$NFT_RPMS_IMAGE"; then
  echo "ERROR: ${NFT_RPMS_IMAGE} is in neither the S3 workflow cache nor Docker Hub." >&2
  echo "A build without S3 credentials can only consume an image that is already" >&2
  echo "published to Docker Hub, and this tag has not been published yet." >&2
  exit 1
fi
