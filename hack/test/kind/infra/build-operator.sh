#!/bin/bash

# This script produces a custom operator build that is used
# in the ST and e2e tests in this repo.
#
# It caches the cloned operator repo across runs. Only the actual Go
# compile and Docker image build run on subsequent invocations.
#
# When DEV_IMAGE_PATH and DEV_IMAGE_TAG are set, the operator is built
# for pushing to a remote registry (no PullNever hack, custom tag/registry).
# The operator will resolve images as:
#   <DEV_IMAGE_REGISTRY>/<DEV_IMAGE_PATH>/<image>:<DEV_IMAGE_TAG>
# e.g., docker.io/caseydavenport/node:my-feature

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

if [ -n "$DEV_IMAGE_PATH" ] && [ -n "$DEV_IMAGE_TAG" ]; then
  # Dev mode: generate a temporary versions file with the custom tag,
  # registry, and imagePath so the operator pulls from the right place.
  VERSIONS_FILE=$(mktemp /tmp/calico_versions_XXXXXX.yml)
  sed -e "s/test-build/${DEV_IMAGE_TAG}/g" \
      -e "/version:/a\\    registry: ${DEV_IMAGE_REGISTRY}/\n    imagePath: ${DEV_IMAGE_PATH}" \
      ../calico_versions.yml > "$VERSIONS_FILE"
  build/_output/bin/gen-versions -os-versions="$VERSIONS_FILE" > pkg/components/calico.go
  rm -f "$VERSIONS_FILE"

  # Set pull policy to Always so clusters pull fresh images on each deploy.
  find . -name '*.go' | xargs sed -i 's/PullIfNotPresent/PullAlways/g'

  # Build operator image and tag for the dev registry.
  make image
  # Construct the full image ref, stripping docker.io/ since Docker Hub doesn't use it.
  if [ "${DEV_IMAGE_REGISTRY}" = "docker.io" ] || [ -z "${DEV_IMAGE_REGISTRY}" ]; then
    OPERATOR_REF="${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
  else
    OPERATOR_REF="${DEV_IMAGE_REGISTRY}/${DEV_IMAGE_PATH}/operator:${DEV_IMAGE_TAG}"
  fi
  docker tag tigera/operator:latest "${OPERATOR_REF}"
else
  # Kind mode: use test-build tag and PullNever.
  build/_output/bin/gen-versions -os-versions=../calico_versions.yml > pkg/components/calico.go
  find . -name '*.go' | xargs sed -i 's/PullIfNotPresent/PullNever/g'

  # Build an operator image for us to use and tag it with a local-only tag.
  make image
  docker tag tigera/operator:latest docker.io/tigera/operator:test-build
fi

popd
# Don't rm -rf operator/ -- keep it cached for next run.
set +e
