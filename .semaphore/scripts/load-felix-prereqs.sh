#!/bin/bash
set -e
set -o pipefail

# load-felix-prereqs.sh: Puts the artifacts the Felix blocks consume in place —
# the pre-built libbpf tree, and the cgo and race variants of the calico binary.
# All three are uploaded to the workflow's S3 area by "Build: calico image".
#
# A build without S3 credentials runs read-only (see .semaphore/s3-cmd), so
# those uploads never happened and there is nothing to download; build the
# artifacts locally instead. With credentials a missing artifact means the
# producer did not run and the cache pipeline is broken, so let it fail.

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "${REPO_ROOT}"
S3_CMD="${REPO_ROOT}/.semaphore/s3-cmd"
ARCH=${ARCH:-amd64}
LIBBPF_A="felix/bpf-gpl/libbpf/src/${ARCH}/libbpf.a"

have_credentials() {
  [[ -n "${CALICO_S3_ACCESS_KEY:-}" && -n "${CALICO_S3_SECRET_KEY:-}" ]]
}

# libbpf first: the cgo and race binaries below are built against it.
if have_credentials; then
  "$S3_CMD" cp "${S3_WORKFLOW_DIR}/libbpf-${ARCH}.tar.zst" "/tmp/libbpf-${ARCH}.tar.zst"
  tar --use-compress-program="zstd -d" -xf "/tmp/libbpf-${ARCH}.tar.zst" -C felix/bpf-gpl
else
  # Consumers export NO_LIBBPF_CLONE so that a cold build fails loudly instead
  # of silently re-cloning and re-exposing the github.com/libbpf HTTP 500
  # flake. This is the one place the clone is intended, so drop the guard.
  echo "No S3 credentials; building libbpf from source"
  env -u NO_LIBBPF_CLONE make -C felix libbpf ARCH="${ARCH}"
fi

# Verify the compiled static lib landed, so a broken tarball fails here rather
# than tripping the NO_LIBBPF_CLONE guard in the middle of a later build.
if [ ! -f "${LIBBPF_A}" ]; then
  echo "ERROR: libbpf is missing its compiled ${LIBBPF_A}" >&2
  exit 1
fi

mkdir -p cmd/calico/bin
if have_credentials; then
  "$S3_CMD" cp "${S3_WORKFLOW_DIR}/calico-cgo-${ARCH}" "cmd/calico/bin/calico-cgo-${ARCH}"
  "$S3_CMD" cp "${S3_WORKFLOW_DIR}/calico-race-${ARCH}" "cmd/calico/bin/calico-race-${ARCH}"
else
  echo "No S3 credentials; building the cgo and race calico binaries from source"
  make -C cmd/calico build-cgo build-race ARCH="${ARCH}"
fi
chmod +x "cmd/calico/bin/calico-cgo-${ARCH}" "cmd/calico/bin/calico-race-${ARCH}"
