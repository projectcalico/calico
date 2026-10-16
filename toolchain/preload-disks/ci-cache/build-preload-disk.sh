#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Build a GKE secondary-boot-disk image with the images CI pulls most already on
# it, so pods skip the pull. Wraps the vendored gke-disk-image-builder in
# toolchain/internal/imager -- see its README for why it is a fork and not a fetch.
#
#   PROJECT=tigera-cc-dev GCS_PATH=gs://<bucket> toolchain/preload-disks/ci-cache/build-preload-disk.sh
#
# Needs gcloud (authed, and application default credentials for the builder),
# docker and make. ~5-8 min. DRY_RUN=true prints what it would build and stops
# before the first gcloud call. Attach the result at node pool CREATE time (there is no update
# flag for it), with image streaming on:
#
#   gcloud container node-pools create <pool> --cluster=<c> --location=<l> \
#     --enable-image-streaming \
#     --secondary-boot-disk=disk-image=projects/$PROJECT/global/images/<IMAGE>,mode=CONTAINER_IMAGE_CACHE
#
# A cluster in another project needs roles/compute.imageUser on this one for BOTH
# its default compute SA and its service-<num>@container-engine-robot SA. Missing
# either fails NODE creation, not pool creation, so it surfaces far from the cause.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLCHAIN="$(cd "$HERE/../.." && pwd)"

# The clusters' own project: cross-project works but needs the IAM noted above.
PROJECT="${PROJECT:?set PROJECT to the GCE project that holds the image}"
ZONE="${ZONE:-us-central1-a}"
GO_BUILD_TAG="$(make --no-print-directory -s -C "$TOOLCHAIN/images/go-build" print-tag)"
# A node pool pins this exact name. GKE caps it at 39 chars (GCE allows 63) and
# only enforces that on attach, so -m fails here instead. "cic" rather than
# "ci-cache" because the go-build tag and the commit need the room.
IMAGE_NAME="${IMAGE_NAME:-$("$TOOLCHAIN/hack/generate-image-name.sh" -p cic -t "$GO_BUILD_TAG" -m 39)}"
# GKE pins an exact image name and cannot follow a family, so this is not for the
# node pool: it is so automation can resolve the newest cache disk with
# images describe-from-family and then create a pool pinned to that name.
IMAGE_FAMILY="${IMAGE_FAMILY:-$("$TOOLCHAIN/hack/generate-image-name.sh" -p ci-cache -t "$GO_BUILD_TAG" -F)}"
DISK_SIZE_GB="${DISK_SIZE_GB:-20}"
# Override where "default" is a legacy network with no subnets (unique-caldron-775
# is one): the builder demands a subnetwork and fails validation without it.
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"
GCS_PATH="${GCS_PATH:?set GCS_PATH to a gs:// bucket/path for the builder logs}"
# Space-separated, each with a tag or digest: the cache hits only the exact ref a
# pod requests, so a floating tag caches nothing. Add anything CI pulls often; the
# default is this repo's go-build image, resolved so it cannot drift.
CONTAINER_IMAGES="${CONTAINER_IMAGES:-docker.io/calico/go-build:${GO_BUILD_TAG}}"

log() { echo "[preload-disk] $*"; }

args=(
  --project-name="$PROJECT"
  --image-name="$IMAGE_NAME"
  --zone="$ZONE"
  --gcs-path="$GCS_PATH"
  --disk-size-gb="$DISK_SIZE_GB"
  --network="$NETWORK"
  --subnet="$SUBNET"
  --image-family-name="$IMAGE_FAMILY"
)
for img in $CONTAINER_IMAGES; do args+=(--container-image="$img"); done

if [ "${DRY_RUN:-false}" = true ]; then
  log "DRY_RUN: would build ${IMAGE_NAME} (${#IMAGE_NAME}/39 chars, family ${IMAGE_FAMILY}) in ${PROJECT}"
  log "DRY_RUN: preloading ${CONTAINER_IMAGES}"
  exit 0
fi

# Unique per commit, so a collision means this commit is already built. Nothing
# is deleted here: a node pool pins an exact name, and removing one out from
# under a live pool breaks node creation.
if gcloud compute images describe "$IMAGE_NAME" --project="$PROJECT" >/dev/null 2>&1; then
  log "image $IMAGE_NAME already exists in $PROJECT -- nothing to rebuild."
  log "to force it: gcloud compute images delete $IMAGE_NAME --project=$PROJECT"
  log "or set IMAGE_NAME=<name> to build under a different name."
  exit 0
fi

log "building disk image ${IMAGE_NAME} (family ${IMAGE_FAMILY}) in ${PROJECT} (network ${NETWORK}/${SUBNET})"
log "preloading: ${CONTAINER_IMAGES}"
# Built in the golang image, so the host needs no Go.
make --no-print-directory -C "$HERE" bin/disk-image-builder
"$HERE/bin/disk-image-builder" "${args[@]}"

log "done: image ${IMAGE_NAME} (project ${PROJECT}, ${#IMAGE_NAME}/39 chars)"
