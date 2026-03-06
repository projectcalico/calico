#!/bin/bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# load_images_on_kind_cluster.sh loads test-build-tagged Docker images onto a kind cluster
# using a single combined tar archive, which is significantly faster than loading each
# image individually (one containerd import per node instead of N).
#
# Required environment variables:
#   KIND - path to the kind binary

set -e

: ${KIND:?KIND must be set to the path of the kind binary}

images=(
    docker.io/tigera/operator:test-build
    calico/node:test-build
    calico/typha:test-build
    calico/apiserver:test-build
    calico/ctl:test-build
    calico/cni:test-build
    calico/csi:test-build
    calico/node-driver-registrar:test-build
    calico/pod2daemon-flexvol:test-build
    calico/kube-controllers:test-build
    calico/goldmane:test-build
    calico/webhooks:test-build
    calico/whisker:test-build
    calico/whisker-backend:test-build
)

# Filter to only images that exist locally — not all may have been built.
to_load=()
for img in "${images[@]}"; do
    if docker image inspect "${img}" &>/dev/null; then
        to_load+=("${img}")
    else
        echo "WARNING: ${img} not found locally, skipping"
    fi
done

if [ ${#to_load[@]} -eq 0 ]; then
    echo "No images to load."
    exit 0
fi

echo "Saving ${#to_load[@]} images into a combined archive..."
combined_tar=$(mktemp --suffix=.tar)
trap "rm -f ${combined_tar}" EXIT

docker save -o "${combined_tar}" "${to_load[@]}"

echo "Loading combined archive onto kind cluster..."
${KIND} load image-archive "${combined_tar}"

echo "All ${#to_load[@]} images loaded successfully."
