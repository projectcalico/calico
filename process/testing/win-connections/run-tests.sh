#!/bin/bash
# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

set -o errexit
set -o nounset
set -o pipefail

CURRENT_DIR=$(dirname "$0")

# Use ${KUBECTL} from ../aso/bin/
KUBECTL="${CURRENT_DIR}/../aso/bin/kubectl"

# Check if kubeconfig exists at ../aso/kubeconfig
ASO_KUBECONFIG="${CURRENT_DIR}/../aso/kubeconfig"
if [ -f "${ASO_KUBECONFIG}" ]; then
    echo "Using kubeconfig from: ${ASO_KUBECONFIG}"
    export KUBECONFIG="${ASO_KUBECONFIG}"
elif [ -n "${1:-}" ]; then
    echo "Using kubeconfig from argument: $1"
    export KUBECONFIG="$1"
else
    echo "ERROR: No kubeconfig found. Either provide as argument or ensure ../aso/kubeconfig exists."
    exit 1
fi

echo "Creating namespace demo..."
${KUBECTL} create ns demo || true

echo "Applying nginx, porter, and client deployments..."
${KUBECTL} apply -f ${CURRENT_DIR}/nginx.yaml
${KUBECTL} apply -f ${CURRENT_DIR}/porter.yaml
${KUBECTL} apply -f ${CURRENT_DIR}/client.yaml

echo "Waiting for linux pods to be ready..."
${KUBECTL} wait pod -l app=nginx --for=condition=Ready -n demo --timeout=30s
${KUBECTL} wait pod -l app=client --for=condition=Ready -n demo --timeout=30s

echo "Windows pods can take a while to become ready... wait for up to 10 minutes..."
${KUBECTL} wait pod -l app=porter --for=condition=Ready -n demo --timeout=600s

echo ""
echo "=========================================="
echo "Running connectivity tests..."
echo "=========================================="

CLIENT_POD="client"
PORTER_POD="porter"

TESTS_FAILED=0

echo ""
echo "Test 1: Client pod (Linux) -> Porter service (Windows) (DNS: porter)"
echo "---------------------------------------------------------------------"
if ! ${KUBECTL} exec -n demo -t ${CLIENT_POD} -- wget -q -O - --timeout=10 http://porter:80; then
    echo "FAILED: Client cannot reach Porter"
    TESTS_FAILED=1
fi

echo ""
echo "Test 2: Porter pod (Windows) -> Nginx service (Linux) (DNS: nginx)"
echo "-------------------------------------------------------------------"
if ! ${KUBECTL} exec -n demo -t ${PORTER_POD} -- powershell -Command "Invoke-WebRequest -Uri http://nginx:80 -UseBasicParsing -TimeoutSec 10"; then
    echo "FAILED: Porter cannot reach Nginx"
    TESTS_FAILED=1
fi

echo ""
if [ ${TESTS_FAILED} -eq 1 ]; then
    echo "=========================================="
    echo "ERROR: One or more connectivity tests failed!"
    echo "=========================================="
    exit 1
fi

echo "=========================================="
echo "All connectivity tests passed!"
echo "=========================================="
