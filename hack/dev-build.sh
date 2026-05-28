#!/usr/bin/env bash
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

# dev-build.sh — Tag and push Calico dev images to a remote registry.
#
# Called by `make image` and `make push`. Not intended to be run
# directly (requires environment variables set by the Makefile).
#
# Usage:
#   dev-build.sh --tag         Tag locally-built images for the dev registry
#   dev-build.sh --operator    Build the operator image if inputs changed
#   dev-build.sh --push        Push dev-tagged images to the registry
#
# Environment (--tag):
#   CALICO_IMAGES    - Space-separated calico/<name>:<tag> source images
#   DEV_IMAGE_PREFIX - <registry>/<path> prefix for dev images
#   DEV_IMAGE_TAG    - Tag to apply
#   ARCH             - Architecture suffix for source tags
#   STAMP_DIR        - Directory for stamp files
#
# Environment (--operator):
#   STAMP_DIR          - Directory for stamp files
#   KIND_INFRA_DIR     - Path to hack/test/kind/infra/
#   OPERATOR_REPO      - Operator git repo (e.g., tigera/operator)
#   OPERATOR_BRANCH    - Operator branch to build
#   DEV_IMAGE_TAG      - Tag for the operator image
#   DEV_IMAGE_REGISTRY - Registry for the operator image
#   DEV_IMAGE_PATH     - Path within the registry
#
# Environment (--push):
#   DEV_IMAGES - Space-separated target image refs to push
#   STAMP_DIR  - Directory for stamp files

set -euo pipefail

# Re-tag locally-built calico images for the dev registry.
tag() {
    for img in $CALICO_IMAGES; do
        base="${img%%:*}"
        name="${base#calico/}"
        dev_img="${DEV_IMAGE_PREFIX}/${name}:${DEV_IMAGE_TAG}"
        docker tag "${base}:latest-${ARCH}" "$dev_img"
    done

    echo "Tagged $(echo $CALICO_IMAGES | wc -w) images as ${DEV_IMAGE_PREFIX}/*:${DEV_IMAGE_TAG}"
}

# Build the operator image if its inputs (tag, registry, repo, branch, versions)
# have changed since the last run.
operator() {
    mkdir -p "$STAMP_DIR"
    versions_hash=$(md5sum "${KIND_INFRA_DIR}/calico_versions.yml" | cut -d' ' -f1)
    cur_inputs="${DEV_IMAGE_TAG}:${DEV_IMAGE_REGISTRY}:${DEV_IMAGE_PATH}:${OPERATOR_REPO}:${OPERATOR_BRANCH}:${versions_hash}"
    stamp="${STAMP_DIR}/operator.inputs"
    prev_inputs=$(cat "$stamp" 2>/dev/null || echo "")

    if [ "$cur_inputs" = "$prev_inputs" ]; then
        echo "Operator unchanged (inputs match)"
    else
        echo "Building operator (inputs changed)..."
        cd "$KIND_INFRA_DIR"
        REPO="$OPERATOR_REPO" \
            BRANCH="$OPERATOR_BRANCH" \
            DEV_IMAGE_TAG="$DEV_IMAGE_TAG" \
            DEV_IMAGE_REGISTRY="$DEV_IMAGE_REGISTRY" \
            DEV_IMAGE_PATH="$DEV_IMAGE_PATH" \
            ./build-operator.sh
        echo "$cur_inputs" > "$stamp"
    fi
}

# Push dev-tagged images to the remote registry. Skips images whose
# docker image ID hasn't changed since the last push.
push() {
    pushed=0
    skipped=0

    for img in $DEV_IMAGES; do
        local_id=$(docker image inspect "$img" --format '{{.Id}}' 2>/dev/null || echo "none")
        stamp_name=$(echo "$img" | tr '/:' '__')
        stamp="${STAMP_DIR}/${stamp_name}.pushed-id"
        prev_id=$(cat "$stamp" 2>/dev/null || echo "")

        if [ "$local_id" = "$prev_id" ]; then
            skipped=$((skipped + 1))
        else
            echo "Pushing $img"
            docker push "$img"
            echo "$local_id" > "$stamp"
            pushed=$((pushed + 1))
        fi
    done

    echo "push complete: $pushed pushed, $skipped already up-to-date"
}

case "${1:-}" in
    --tag)      tag ;;
    --operator) operator ;;
    --push)     push ;;
    *)
        echo "Usage: $0 --tag | --operator | --push" >&2
        exit 1
        ;;
esac
