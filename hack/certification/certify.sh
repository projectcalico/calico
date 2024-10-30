#!/bin/bash

# Copyright (c) 2024 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script runs Openshift preflight against Calico images and optionally uploads the results to Openshift Connect for the certification process.
# In addition, the certification process also requires the following, which are NOT handled by this script:
# - the operator metadata bundle (see the tigera/operator repo) to be submitted by PR
#   to https://github.com/redhat-openshift-ecosystem/certified-operators
# - running the Openshift End-to-End tests - we run them for CNI and CNV.  The results need to be passed to the Certification team for verification.

set -x

# Version of openshift preflight to use
PREFLIGHT_TAG="${PREFLIGHT_TAG:-stable}"

# Calico versions to test. The Operator and Calico versions must match.
OPERATOR_VERSION="${OPERATOR_VERSION:-master}"
CALICO_VERSION="${CALICO_VERSION:-master}"

# Redhat API key, needed for submitting the images
RH_API_KEY="${RH_API_KEY:-""}"

# SUBMIT controls whether this is a dry run or a "real" run.  Set to "--submit" to actually submit the images to the certification system.
SUBMIT="${SUBMIT:-""}"

podman pull quay.io/opdev/preflight:$PREFLIGHT_TAG

declare -a LINUX_PLATFORMS=(
    "amd64"
    "arm64"
    "s390x"
    "ppc64le"
    )

# dictionaries of Openshift Connect project IDs
declare -A calico_image_project=(
    ["node"]="5e61a7ab06151b52d45a1148"
    ["cni"]="5e7e3829afa92f4963e7d9db"
    ["kube-controllers"]="5e6054f906151b52d45a1081"
    ["typha"]="5e60724f2f3c1acdd05f6012"
    ["pod2daemon-flexvol"]="5e6054fb06151b52d45a1082"
    ["apiserver"]="64b7c1758357ec6208cd2c72"
    ["csi"]="64b7c10b46357734e64690ac"
    ["node-driver-registrar"]="64c01702093679e0f47fa153"
    ["flannel-migration-controller"]="5e619bec2c5f183d03415978"
    ["dikastes"]="5e619e432f3c1acdd05f6240"
)

declare -A operator_image_project=(
    ["operator"]="5e60736f2f3c1acdd05f6014"
)

# # The openshift certification process doesn't support windows images currently
# declare -a WINDOWS_PLATFORMS=(
# "windows/amd64/10.0.17763.5122"
# "windows/amd64/10.0.19041.1415"
# "windows/amd64/10.0.19042.1889"
# "windows/amd64/10.0.20348.2113"
# )

# # The openshift certification process doesn't support windows images currently
# declare -A windows_image_project=(
#     ["windows-upgrade"]="64c01760bb2ac622579092af"  # windows
#     ["node-windows"]=""
#     ["cni-windows"]=""
# )

certify_image () {
    for PLATFORM in "${PLATFORMS[@]}"; do
        mkdir -p "${IMAGE}"
        pushd "${IMAGE}" || exit
        podman run -it --rm --security-opt=label=disable \
            --env PFLT_PLATFORM="$PLATFORM" \
            --env PFLT_LOGLEVEL=trace \
            --env PFLT_ARTIFACTS=/artifacts \
            --env PFLT_LOGFILE=/artifacts/preflight.log \
            --env PFLT_CERTIFICATION_PROJECT_ID="${PROJECT}" \
            --env PFLT_PYXIS_API_TOKEN="$RH_API_KEY" \
            -v "$PWD":/artifacts \
            quay.io/opdev/preflight:$PREFLIGHT_TAG check container ${ORG}/${IMAGE}:${VERSION} ${SUBMIT}
        popd || exit
    done
}

mkdir -p output-${CALICO_VERSION}
pushd output-${CALICO_VERSION} || exit

for IMAGE in "${!calico_image_project[@]}"; do
    PLATFORMS=("${LINUX_PLATFORMS[@]}")
    ORG="quay.io/calico"
    PROJECT="${calico_image_project[${IMAGE}]}"
    VERSION=${CALICO_VERSION}
    certify_image
done

for IMAGE in "${!operator_image_project[@]}"; do
    PLATFORMS=("${LINUX_PLATFORMS[@]}")
    ORG="quay.io/tigera"
    PROJECT="${operator_image_project[${IMAGE}]}"
    VERSION=${OPERATOR_VERSION}
    certify_image
done

# # The openshift certification process doesn't support windows images currently
# for IMAGE in "${!windows_image_project[@]}"; do
#     PLATFORMS=("${WINDOWS_PLATFORMS[@]}")
#     ORG="quay.io/calico"
#     PROJECT="${windows_image_project[${IMAGE}]}"
#     VERSION=${CALICO_VERSION}
#     certify_image
# done

# Consolidate the results into per-arch files for easier review
for PLATFORM in "${PLATFORMS[@]}"; do
    cat ./*/"$PLATFORM"/results.json > "$PLATFORM"-results.json
done

popd || exit
