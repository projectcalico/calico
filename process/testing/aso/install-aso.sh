#!/bin/bash
# Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

: "${KINDEST_NODE_VERSION:=v1.31.0}"
CRD_PATTERN="resources.azure.com/*;containerservice.azure.com/*;compute.azure.com/*;network.azure.com/*"

# Utilities
: ${KIND:=./bin/kind}
: ${KUBECTL:=./bin/kubectl}
: ${CMCTL:=./bin/cmctl}
: ${ASOCTL:=./bin/asoctl}
: ${HELM:=./bin/helm}

# Create management cluster
${KIND} create cluster --image kindest/node:${KINDEST_NODE_VERSION} --name kind
${KUBECTL} wait node kind-control-plane --for=condition=ready --timeout=90s

# Install cert-manager
echo; echo "Wait for cert manager to be installed ..."
${KUBECTL} apply -f https://github.com/jetstack/cert-manager/releases/download/v1.14.1/cert-manager.yaml
${CMCTL} check api --wait=2m

echo; echo "Installing ASO..."

${HELM} repo add aso2 https://raw.githubusercontent.com/Azure/azure-service-operator/main/v2/charts
${HELM} upgrade --install aso2 aso2/azure-service-operator \
    --create-namespace \
    --namespace=azureserviceoperator-system \
    --set crdPattern=${CRD_PATTERN}

# Wait for ASO deployments
echo "Wait for ASO controller manager to be ready (up to 5m) ..."
${KUBECTL} wait --for=condition=available --timeout=5m -n azureserviceoperator-system deployment azureserviceoperator-controller-manager
echo "ASO installed and the controller manager is ready."
