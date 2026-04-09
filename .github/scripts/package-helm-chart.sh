#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# Packages the tigera-operator helm chart with custom operator image refs
# and pushes it to an OCI registry.
# Required env vars: TAG, REGISTRY, IMAGE_PATH
# Outputs: chart_ref (written to GITHUB_OUTPUT)
set -euo pipefail

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
helm package "${WORK_DIR}/tigera-operator" --version "${CHART_VERSION}"

CHART_REF="oci://${REGISTRY}/${IMAGE_PATH}/charts/tigera-operator:${CHART_VERSION}"
helm push "tigera-operator-${CHART_VERSION}.tgz" "oci://${REGISTRY}/${IMAGE_PATH}/charts"

echo "Chart pushed to ${CHART_REF}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "chart_ref=${CHART_REF}" >> "$GITHUB_OUTPUT"
fi
