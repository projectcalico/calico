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

# Packages the tigera-operator helm chart with custom operator image refs
# and pushes it to an OCI registry.
# Required env vars: TAG, REGISTRY, IMAGE_PATH
# Optional env vars: HELM (path to helm binary, default: helm)
# Outputs: chart_ref (written to GITHUB_OUTPUT when running in GHA)
set -euo pipefail

HELM="${HELM:-helm}"

: "${TAG:?[ERROR] TAG is required.}"
: "${REGISTRY:?[ERROR] REGISTRY is required.}"
: "${IMAGE_PATH:?[ERROR] IMAGE_PATH is required.}"

CHART_DIR="charts/tigera-operator"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# Copy the chart to a temp dir so we don't modify the source tree.
cp -r "${CHART_DIR}" "${WORK_DIR}/tigera-operator"

# Patch chart values with the custom operator image coordinates.
sed -i "s|image: tigera/operator|image: ${IMAGE_PATH}/operator|" "${WORK_DIR}/tigera-operator/values.yaml"
sed -i "s|version: master|version: ${TAG}|" "${WORK_DIR}/tigera-operator/values.yaml"
sed -i "s|registry: quay.io|registry: ${REGISTRY}|" "${WORK_DIR}/tigera-operator/values.yaml"

CHART_VERSION="0.0.0-${TAG}"
"${HELM}" package "${WORK_DIR}/tigera-operator" --version "${CHART_VERSION}" --destination "${WORK_DIR}"

CHART_REF="oci://${REGISTRY}/${IMAGE_PATH}/charts/tigera-operator:${CHART_VERSION}"
"${HELM}" push "${WORK_DIR}/tigera-operator-${CHART_VERSION}.tgz" "oci://${REGISTRY}/${IMAGE_PATH}/charts"

echo "Chart pushed to ${CHART_REF}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "chart_ref=${CHART_REF}" >> "$GITHUB_OUTPUT"
fi
