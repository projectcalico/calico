#!/bin/bash

# This script produces a custom operator build that is used
# in the ST and e2e tests in this repo.

# Clone the repository if needed.
set -e
REPO=${REPO:-tigera/operator}
BRANCH=${BRANCH:-master}

rm -rf operator/
echo "Cloning https://github.com/${REPO} @ ${BRANCH}"
git clone --depth=1 https://github.com/${REPO} -b ${BRANCH} operator

# Modify the versions that are in-use to match our locally built images.
pushd operator
make build/_output/bin/gen-versions
build/_output/bin/gen-versions -os-versions=../calico_versions.yml > pkg/components/calico.go

# Modify pull policy to be "Never".
find . -name '*.go' | xargs sed -i 's/PullIfNotPresent/PullNever/g'

# Build an operator image for us to use and tag it with a local-only tag.
make image
docker tag tigera/operator:latest docker.io/tigera/operator:test-build

# Clean up after ourselves.
popd
rm -rf operator/
set +e
