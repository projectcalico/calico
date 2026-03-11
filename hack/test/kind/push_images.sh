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

# push_images.sh pushes Docker images to a local registry for use by a kind cluster.
# Docker push is incremental by layer, so unchanged layers are not re-transferred.
#
# Usage: push_images.sh <image1> <image2> ...
#
# Optional environment variables:
#   KIND_REGISTRY - registry address (default: localhost:5001)

set -e

REGISTRY=${KIND_REGISTRY:-localhost:5001}

if [ $# -eq 0 ]; then
    echo "Usage: $0 <image1> <image2> ..."
    echo "No images specified."
    exit 0
fi

pushed=0
skipped=0

for img in "$@"; do
    if ! docker image inspect "${img}" &>/dev/null; then
        echo "WARNING: ${img} not found locally, skipping"
        skipped=$((skipped + 1))
        continue
    fi
    remote="${REGISTRY}/${img}"
    docker tag "${img}" "${remote}"
    docker push --quiet "${remote}"
    echo "Pushed: ${img}"
    pushed=$((pushed + 1))
done

echo "Pushed ${pushed} images to ${REGISTRY} (${skipped} skipped)."
