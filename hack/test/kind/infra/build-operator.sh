#!/bin/bash

# This script produces a custom operator build that is used
# in the ST and e2e tests in this repo.
#
# It caches the cloned operator repo across runs. Only the actual Go
# compile and Docker image build run on subsequent invocations.
#
# Required env: DEV_IMAGE_REGISTRY, DEV_IMAGE_PATH, DEV_IMAGE_TAG. The
# operator resolves images as <DEV_IMAGE_REGISTRY>/<DEV_IMAGE_PATH>/<image>:<DEV_IMAGE_TAG>
# (e.g., kind-registry:5000/calico/node:test-build for kind, or
# docker.io/myuser/node:my-feature for personal dev).

set -e
REPO=${REPO:-tigera/operator}
BRANCH=${BRANCH:-master}

# Reuse the existing clone if branch matches, otherwise start fresh.
if [ -d operator/.git ]; then
  existing_branch=$(git -C operator rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  if [ "$existing_branch" = "$BRANCH" ]; then
    echo "Reusing cached operator clone (branch: ${BRANCH}), pulling latest..."
    git -C operator fetch --depth=1 origin ${BRANCH}
    git -C operator reset --hard origin/${BRANCH}
  else
    echo "Branch changed (${existing_branch} -> ${BRANCH}), re-cloning..."
    rm -rf operator/
    git clone --depth=1 https://github.com/${REPO} -b ${BRANCH} operator
  fi
else
  echo "Cloning https://github.com/${REPO} @ ${BRANCH}"
  git clone --depth=1 https://github.com/${REPO} -b ${BRANCH} operator
fi

pushd operator

if [ -n "$COMMIT" ]; then
  # If the latest operator has issues, fetch a known working commit as a workaround.
  echo "Fetch commit $COMMIT"
  git fetch origin $COMMIT
  git checkout $COMMIT
fi

make build/_output/bin/gen-versions

: "${DEV_IMAGE_REGISTRY:?DEV_IMAGE_REGISTRY must be set}"
: "${DEV_IMAGE_PATH:?DEV_IMAGE_PATH must be set}"
: "${DEV_IMAGE_TAG:?DEV_IMAGE_TAG must be set}"

# Generate a temporary versions file with the custom tag, registry, and
# imagePath so the operator resolves component images at the right location.
VERSIONS_FILE=$(mktemp /tmp/calico_versions_XXXXXX.yml)
sed -e "s/test-build/${DEV_IMAGE_TAG}/g" \
    -e "/version:/a\\    registry: ${DEV_IMAGE_REGISTRY}/\n    imagePath: ${DEV_IMAGE_PATH}" \
    ../calico_versions.yml > "$VERSIONS_FILE"
build/_output/bin/gen-versions -os-versions="$VERSIONS_FILE" > pkg/components/calico.go
rm -f "$VERSIONS_FILE"

# Pull every image fresh so clusters pick up new digests under stable tags.
find . -name '*.go' | xargs sed -i 's/PullIfNotPresent/PullAlways/g'

make image
# Strip docker.io/ since Docker Hub doesn't use it.
if [ "${DEV_IMAGE_REGISTRY}" = "docker.io" ]; then
  OPERATOR_REF="${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
else
  OPERATOR_REF="${DEV_IMAGE_REGISTRY}/${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
fi
docker tag tigera/operator:latest "${OPERATOR_REF}"

popd
# Don't rm -rf operator/ -- keep it cached for next run.
set +e
