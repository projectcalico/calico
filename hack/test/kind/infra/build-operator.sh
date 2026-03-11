#!/bin/bash

# This script produces a custom operator build that is used
# in the ST and e2e tests in this repo.
#
# It caches the cloned operator repo and downloaded artifacts (helm binary,
# Istio charts, Go build cache) across runs. Only the actual Go compile and
# Docker image build run on subsequent invocations.

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
build/_output/bin/gen-versions -os-versions=../calico_versions.yml > pkg/components/calico.go

# Modify pull policy to be "Always" so the operator pulls from the local registry.
find . -name '*.go' | xargs sed -i 's/PullIfNotPresent/PullAlways/g'

# Build an operator image for us to use and push it to the local registry.
make image
docker tag tigera/operator:latest docker.io/tigera/operator:test-build
docker tag tigera/operator:latest localhost:5001/tigera/operator:test-build
docker push --quiet localhost:5001/tigera/operator:test-build

popd
# Don't rm -rf operator/ -- keep it cached for next run.
set +e
