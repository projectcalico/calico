#!/bin/bash

# The operator image the ST and e2e tests use, built from operator/ so it
# matches the commit under test.
#
# Required env: DEV_IMAGE_REGISTRY, DEV_IMAGE_PATH, DEV_IMAGE_TAG. The
# operator resolves images as <DEV_IMAGE_REGISTRY>/<DEV_IMAGE_PATH>/<image>:<DEV_IMAGE_TAG>
# (e.g., localhost:5000/calico/node:test-build for kind, or
# docker.io/myuser/node:my-feature for personal dev).

set -e

INFRA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OPERATOR_DIR=$(cd "${INFRA_DIR}/../../../../operator" && pwd)

: "${DEV_IMAGE_REGISTRY:?DEV_IMAGE_REGISTRY must be set}"
: "${DEV_IMAGE_PATH:?DEV_IMAGE_PATH must be set}"
: "${DEV_IMAGE_TAG:?DEV_IMAGE_TAG must be set}"

pushd "${OPERATOR_DIR}"

make dev-image \
    CALICO_VERSION="${DEV_IMAGE_TAG}" \
    CALICO_REGISTRY="${DEV_IMAGE_REGISTRY}" \
    CALICO_IMAGE_PATH="${DEV_IMAGE_PATH}"

# Strip docker.io/ since Docker Hub doesn't use it.
if [ "${DEV_IMAGE_REGISTRY}" = "docker.io" ]; then
  OPERATOR_REF="${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
else
  OPERATOR_REF="${DEV_IMAGE_REGISTRY}/${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
fi
docker tag tigera/operator:latest "${OPERATOR_REF}"

popd
