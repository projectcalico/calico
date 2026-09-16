#!/bin/bash
set -e
set -o pipefail

# load-nft-rpms.sh: Makes the patched nftables RPMs producer image available
# locally, so a consumer Dockerfile's `FROM ${NFT_RPMS_IMAGE}` resolves without
# reaching out mid-build. Run by every block that lists "Build: nftables RPMs"
# in its dependencies.
#
# The image normally arrives as a tarball in the workflow's storage, put there
# by build-nft-rpms.sh. Falling back to a Docker Hub pull is safe here in a way
# it would not be for an image built from the branch: the tag is a hash of the
# specs and patches, so a published one holds exactly these RPMs.

ARCH=$1
if [ -z "$ARCH" ]; then
  echo "Usage: $0 <arch>"
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
S3_CMD="${REPO_ROOT}/.semaphore/s3-cmd"

NFT_RPMS_TAG=$(make --no-print-directory -C "${REPO_ROOT}/hack/rpms/nftables" print-tag)
NFT_RPMS_IMAGE="calico/nftables-rpms:${NFT_RPMS_TAG}-${ARCH}"
CACHE_NAME="nft-rpms-${ARCH}.tar.zst"
CACHE_PATH="${S3_WORKFLOW_DIR}/${CACHE_NAME}"

fetch_tarball() {
  if [ -n "${CI_ARTIFACT_STORAGE:-}" ]; then
    ( cd /tmp && artifact pull workflow "${CACHE_NAME}" )
    return
  fi
  "$S3_CMD" cp "$CACHE_PATH" "/tmp/${CACHE_NAME}"
}

if docker image inspect "$NFT_RPMS_IMAGE" >/dev/null 2>&1; then
  echo "${NFT_RPMS_IMAGE} is already present locally"
  exit 0
fi

if fetch_tarball; then
  echo "Loading ${NFT_RPMS_IMAGE} from the workflow cache"
  zstd -d --rm "/tmp/${CACHE_NAME}"
  docker load -i "/tmp/${CACHE_NAME%.zst}"
  rm -f "/tmp/${CACHE_NAME%.zst}"
  exit 0
fi

echo "No cached tarball; pulling ${NFT_RPMS_IMAGE} from Docker Hub instead"
if ! docker pull "$NFT_RPMS_IMAGE"; then
  echo "ERROR: ${NFT_RPMS_IMAGE} is in neither the workflow cache nor Docker Hub." >&2
  echo "Only a tag that has already been published can be consumed without a" >&2
  echo "producer run, and this one has not been." >&2
  exit 1
fi
