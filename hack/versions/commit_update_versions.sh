#!/bin/bash

set -o errexit
set -o nounset

GIT_TOPLEVEL=$(git rev-parse --show-toplevel)

if [[ $(pwd) != $GIT_TOPLEVEL ]]; then
    cd GIT_TOPLEVEL
fi

git add charts/calico/values.yaml charts/tigera-operator/values.yaml
git add manifests/
git commit -m "[CI] Updating charts and manifests for Calico $(bin/yq .version charts/calico/values.yaml)" \
           -m "Automatic update from Semaphore release process"

