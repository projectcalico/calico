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

make build/_output/bin/gen-versions

# Repoint every component in the operator's versions file at the dev registry
# and tag. Put the committed calico.go back once the image is built.
COMPONENTS="${OPERATOR_DIR}/pkg/components/calico.go"
trap 'git -C "${OPERATOR_DIR}" checkout -- pkg/components/calico.go' EXIT INT TERM

VERSIONS_FILE=$(mktemp /tmp/calico_versions_XXXXXX.yml)
sed -e "/^ *\(registry\|imagePath\):/d" \
    -e "s|^\( *\)version: .*|\1version: ${DEV_IMAGE_TAG}\n\1registry: ${DEV_IMAGE_REGISTRY}/\n\1imagePath: ${DEV_IMAGE_PATH}|" \
    "${OPERATOR_DIR}/config/calico_versions.yml" > "${VERSIONS_FILE}"
build/_output/bin/gen-versions -os-versions="${VERSIONS_FILE}" > "${COMPONENTS}"
rm -f "${VERSIONS_FILE}"

make image
# Strip docker.io/ since Docker Hub doesn't use it.
if [ "${DEV_IMAGE_REGISTRY}" = "docker.io" ]; then
  OPERATOR_REF="${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
else
  OPERATOR_REF="${DEV_IMAGE_REGISTRY}/${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
fi
docker tag tigera/operator:latest "${OPERATOR_REF}"

popd
