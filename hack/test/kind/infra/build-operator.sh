#!/bin/bash

# This script produces a custom operator build that is used
# in the ST and e2e tests in this repo.
#
# When DEV_IMAGE_PATH and DEV_IMAGE_TAG are set, the operator is built
# for pushing to a remote registry (no PullNever hack, custom tag/registry).
# The operator will resolve images as:
#   <DEV_IMAGE_REGISTRY>/<DEV_IMAGE_PATH>/<image>:<DEV_IMAGE_TAG>
# e.g., docker.io/caseydavenport/node:my-feature

# Clone the repository if needed.
set -e
REPO=${REPO:-tigera/operator}
BRANCH=${BRANCH:-master}

rm -rf operator/
echo "Cloning https://github.com/${REPO} @ ${BRANCH}"
git clone --depth=1 https://github.com/${REPO} -b ${BRANCH} operator

# Modify the versions that are in-use to match our locally built images.
pushd operator

if [ -n "$COMMIT" ]; then
  # If the latest operator has issues, fetch a known working commit as a workaround."
  echo "Fetch commit $COMMIT"
  git fetch origin $COMMIT
  git checkout $COMMIT
fi

make build/_output/bin/gen-versions

if [ -n "$DEV_IMAGE_PATH" ] && [ -n "$DEV_IMAGE_TAG" ]; then
  # Dev mode: generate a temporary versions file with the custom tag,
  # registry, and imagePath so the operator pulls from the right place.
  VERSIONS_FILE=$(mktemp /tmp/calico_versions_XXXXXX.yml)
  sed -e "s/test-build/${DEV_IMAGE_TAG}/g" \
      -e "/version:/a\\    registry: ${DEV_IMAGE_REGISTRY}/\n    imagePath: ${DEV_IMAGE_PATH}" \
      ../calico_versions.yml > "$VERSIONS_FILE"
  build/_output/bin/gen-versions -os-versions="$VERSIONS_FILE" > pkg/components/calico.go
  rm -f "$VERSIONS_FILE"

  # Build operator image and tag for the dev registry.
  make image
  docker tag tigera/operator:latest "${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
else
  # Kind mode: use test-build tag and PullNever.
  build/_output/bin/gen-versions -os-versions=../calico_versions.yml > pkg/components/calico.go
  find . -name '*.go' | xargs sed -i 's/PullIfNotPresent/PullNever/g'

  make image
  docker tag tigera/operator:latest docker.io/tigera/operator:test-build
fi

# Clean up after ourselves.
popd
rm -rf operator/
set +e
