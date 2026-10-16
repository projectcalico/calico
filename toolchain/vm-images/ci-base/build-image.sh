#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Build (or refresh) the ci-base CI VM image: a throwaway builder VM runs
# provision.sh, its disk is snapshotted into FAMILY, the builder is deleted.
# createvm boots from FAMILY, so it always gets the newest.
#
#   PROJECT=unique-caldron-775 toolchain/vm-images/ci-base/build-image.sh
#
# Needs gcloud (authed, compute instance + image create/delete) and make.
# ~3-4 min. DRY_RUN=true prints what it would build and stops before the first
# gcloud call.
set -euo pipefail

PROJECT="${PROJECT:?set PROJECT to the GCE project that holds the image}"
ZONE="${ZONE:-us-central1-a}"
# Left empty so generate-image-name.sh decides: a release build goes to its
# go-build tag's family, anything else to its own. Pinning one here puts every
# build in the same family, and since a family resolves to its newest member,
# a PR build would become what every CI VM boots from.
FAMILY="${FAMILY:-}"
BUILDER="${BUILDER:-ci-img-builder-$$}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLCHAIN="$(cd "$HERE/../.." && pwd)"
REPO="$(cd "$TOOLCHAIN/.." && pwd)"

log() { echo "[build-image] $*"; }
# Reads a metadata.mk variable. The $(...) is make syntax, not shell.
# shellcheck disable=SC2016
metadata() { make --no-print-directory -s -C "$REPO" -f metadata.mk --eval 'print-%: ; @echo $($*)' "print-$1"; }

# The VM stands in for a calico/go-build container, so it must see the same Go
# and pre-pull that exact image.
GO_BUILD_TAG="$(make --no-print-directory -s -C "$TOOLCHAIN/images/go-build" print-tag)"
GO_VERSION="${GO_VERSION:-$(metadata GO_VERSION)}"
GO_SHA256="${GO_SHA256:-$(awk -v t="go${GO_VERSION}.linux-amd64.tar.gz" '$2 == t {print $1}' "$TOOLCHAIN/images/go-build/go.sha256")}"
[ -n "$GO_SHA256" ] || { echo "no amd64 checksum for go${GO_VERSION} in toolchain/images/go-build/go.sha256" >&2; exit 1; }
GO_BUILD_IMAGE="${GO_BUILD_IMAGE:-calico/go-build:${GO_BUILD_TAG}}"
KUBECTL_VERSION="${KUBECTL_VERSION:-$(metadata K8S_VERSION)}"
log "go $GO_VERSION, kubectl $KUBECTL_VERSION, prepulling $GO_BUILD_IMAGE"

IMAGE="${IMAGE:-$("$TOOLCHAIN/hack/generate-image-name.sh" -p ci-base -t "$GO_BUILD_TAG")}"
FAMILY="${FAMILY:-$("$TOOLCHAIN/hack/generate-image-name.sh" -p ci-base -t "$GO_BUILD_TAG" -F)}"
log "image name: $IMAGE (family $FAMILY)"

# kind and gh are pinned here, so an image build is reproducible from a commit.
# An environment override of any of them wins.
VM_VERSIONS="$HERE/versions.env"
eval "$(sed -n 's/^\([A-Z_]*\)=\(.*\)$/: "${\1:=\2}"/p' "$VM_VERSIONS")"
[ -n "$KIND_NODE_IMAGES" ] || { echo "KIND_NODE_IMAGES is empty in $VM_VERSIONS" >&2; exit 1; }
log "kind $KIND_VERSION, gh $GH_VERSION (from $VM_VERSIONS)"
for img in $KIND_NODE_IMAGES; do log "  node image: $img"; done

if [ "${DRY_RUN:-false}" = true ]; then
  log "DRY_RUN: would build $IMAGE in family $FAMILY, project $PROJECT, zone $ZONE"
  exit 0
fi

# Names are unique per commit, so a collision means this exact thing is
# already built. Nothing is deleted to make room; the family moves to whatever
# is newest.
if gcloud compute images describe "$IMAGE" --project="$PROJECT" >/dev/null 2>&1; then
  log "image $IMAGE already exists in $PROJECT -- nothing to rebuild."
  log "to force it: gcloud compute images delete $IMAGE --project=$PROJECT"
  log "or set IMAGE=<name> to build under a different name."
  exit 0
fi

# provision.sh runs as the builder's startup-script and cannot read this repo.
STARTUP="$(mktemp)"
{
  echo '#!/usr/bin/env bash'
  echo '# Preamble injected by build-image.sh.'
  printf 'export GO_VERSION=%q\n' "$GO_VERSION"
  printf 'export GO_SHA256=%q\n' "$GO_SHA256"
  printf 'export GO_BUILD_IMAGE=%q\n' "$GO_BUILD_IMAGE"
  printf 'export KUBECTL_VERSION=%q\n' "$KUBECTL_VERSION"
  printf 'export KIND_VERSION=%q\n' "$KIND_VERSION"
  printf 'export KIND_NODE_IMAGES=%q\n' "$KIND_NODE_IMAGES"
  printf 'export GH_VERSION=%q\n' "$GH_VERSION"
  tail -n +2 "$HERE/provision.sh" # its shebang is replaced by the one above
} >"$STARTUP"

cleanup() {
  rm -f "$STARTUP"
  gcloud --quiet compute instances delete "$BUILDER" --project="$PROJECT" --zone="$ZONE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

log "creating builder $BUILDER in $ZONE"
# max-run-duration so the builder cannot outlive the job: the trap misses a
# SIGKILL, and the poll below can run past the pipeline's 30-minute limit.
gcloud compute instances create "$BUILDER" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=e2-standard-8 \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB --boot-disk-type=pd-ssd \
  --max-run-duration=60m --instance-termination-action=DELETE \
  --metadata-from-file startup-script="$STARTUP"

log "waiting for provision.sh (~2-3 min)"
ready=""
for _ in $(seq 1 120); do
  if gcloud --quiet compute ssh "ubuntu@$BUILDER" --project="$PROJECT" --zone="$ZONE" \
       --ssh-flag="-o BatchMode=yes -o ConnectTimeout=10" --command='test -e /var/run/provision-done' 2>/dev/null; then
    ready=1; break
  fi
  sleep 10
done
if [ -z "$ready" ]; then
  log "provision timed out; serial console tail:"
  gcloud compute instances get-serial-port-output "$BUILDER" --project="$PROJECT" --zone="$ZONE" 2>/dev/null | tail -100 || true
  exit 1
fi

# Enforcing, not informational: every binary must run and every pre-pulled image
# must be in the cache, or nothing is published from this builder.
log "verifying the toolchain before snapshotting"
if ! gcloud --quiet compute ssh "ubuntu@$BUILDER" --project="$PROJECT" --zone="$ZONE" \
  --command="set -e
    docker --version
    /usr/local/go/bin/go version
    kind version
    kubectl version --client
    gh --version
    echo '--- baked images ---'
    sudo docker images --format '{{.Repository}}:{{.Tag}} ({{.Size}})'
    for img in $GO_BUILD_IMAGE $KIND_NODE_IMAGES registry:2; do
      sudo docker image inspect \"\$img\" >/dev/null || { echo \"missing from cache: \$img\"; exit 1; }
    done"; then
  log "verification FAILED -- not publishing an image from this builder"
  exit 1
fi

log "stopping builder for a consistent disk"
gcloud --quiet compute instances stop "$BUILDER" --project="$PROJECT" --zone="$ZONE"

# Dots become dashes, matching the munged form in the image name -- label values
# may not contain dots, so this cannot hold the tag verbatim.
log "creating image $IMAGE in family $FAMILY"
gcloud compute images create "$IMAGE" --project="$PROJECT" \
  --source-disk="$BUILDER" --source-disk-zone="$ZONE" --family="$FAMILY" \
  --labels="go-build-tag=$(echo "$GO_BUILD_IMAGE" | sed 's|.*:||; s|\.|-|g')"

log "done: image $IMAGE (family $FAMILY, project $PROJECT). createvm: GOOGLE_VM_IMAGE_PROJECT=$PROJECT GOOGLE_VM_IMAGE_FAMILY=$FAMILY"
