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

# load_images.sh loads Docker images onto a kind cluster.
# It compares local Docker image IDs against what's already on the cluster and only loads
# images that have changed, which avoids re-transferring unchanged images (~1.4GB) on
# incremental rebuilds.
#
# Usage: load_images.sh <image1> <image2> ...
#
# Required environment variables:
#   KIND      - path to the kind binary
#   KIND_NAME - name of the kind cluster to load images onto

set -e

: ${KIND:?KIND must be set to the path of the kind binary}
: ${KIND_NAME:?KIND_NAME must be set to the name of the kind cluster}

if [ $# -eq 0 ]; then
    echo "Usage: $0 <image1> <image2> ..."
    echo "No images specified."
    exit 0
fi

images=("$@")

# Filter to only images that exist locally — not all may have been built.
local_images=()
for img in "${images[@]}"; do
    if docker image inspect "${img}" &>/dev/null; then
        local_images+=("${img}")
    else
        echo "WARNING: ${img} not found locally, skipping"
    fi
done

if [ ${#local_images[@]} -eq 0 ]; then
    echo "No images to load."
    exit 0
fi

# Build a map of image tag -> image ID for images already on the cluster.
# We only need to check one node since kind load targets all nodes.
node=$(${KIND} get nodes --name "${KIND_NAME}" | head -1)
declare -A node_ids
if [ -n "$node" ]; then
    while IFS=' ' read -r tag id; do
        node_ids["$tag"]="$id"
    done < <(docker exec "$node" crictl images -o json 2>/dev/null | jq -r '.images[] | "\(.repoTags[0]) \(.id)"')
fi

# Compare local image IDs against the cluster and collect only changed images.
to_load=()
skipped=0
for img in "${local_images[@]}"; do
    local_id=$(docker image inspect "$img" --format '{{.Id}}')

    # crictl uses fully-qualified names (docker.io/ prefix).
    if [[ "$img" != *"/"*"/"* ]]; then
        fq_img="docker.io/$img"
    else
        fq_img="$img"
    fi

    node_id="${node_ids[$fq_img]:-}"
    if [ "$local_id" = "$node_id" ]; then
        echo "Unchanged: ${img}"
        skipped=$((skipped + 1))
    else
        to_load+=("$img")
    fi
done

if [ ${#to_load[@]} -eq 0 ]; then
    echo "All ${skipped} images already up to date on cluster."
    exit 0
fi

echo "Loading ${#to_load[@]} changed images (${skipped} unchanged, skipped)..."

combined_tar=$(mktemp --suffix=.tar)
trap "rm -f ${combined_tar}" EXIT

docker save -o "${combined_tar}" "${to_load[@]}"

${KIND} load image-archive "${combined_tar}" --name "${KIND_NAME}"

echo "Loaded ${#to_load[@]} images successfully."
