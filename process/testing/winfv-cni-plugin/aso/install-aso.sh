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

. ./utils.sh

# Verify the required Environment Variables are present.
: "${AZURE_SUBSCRIPTION_ID:?Environment variable empty or not defined.}"
: "${AZURE_TENANT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_SECRET:?Environment variable empty or not defined.}"

CRD_PATTERN="resources.azure.com/*;containerservice.azure.com/*;compute.azure.com/*;network.azure.com/*"
SUFFIX=""

# Utilities
: ${KIND:=./bin/kind}
: ${KUBECTL:=./bin/kubectl}
: ${CMCTL:=./bin/cmctl}
: ${ASOCTL:=./bin/asoctl}

# Create management cluster
${KIND} create cluster --image kindest/node:${KUBE_VERSION} --name kind${SUFFIX}
${KUBECTL} wait node kind${SUFFIX}-control-plane --for=condition=ready --timeout=90s

# Install cert-manager
echo; echo "Wait for cert manager to be installed ..."
${KUBECTL} apply -f https://github.com/jetstack/cert-manager/releases/download/v1.14.1/cert-manager.yaml
${CMCTL} check api --wait=2m

echo; echo "Installing ASO ..."

# We are not able to call asoctl in semaphore VM with ubuntu 20.04.
# bin/asoctl: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by bin/asoctl)
# The workaround is to have the manifests generated in advance. 
file="asoctl-generated-manifests-v2.6.0.yaml"
# Check if the file exists in the current directory
if [ -f "$file" ]; then
    echo "The file '$file' exists in the current directory."
    ${KUBECTL} apply -f $file
else
    # Install ASO https://azure.github.io/azure-service-operator/guide/installing-from-yaml/
    ${ASOCTL} export template --version v2.6.0 --crd-pattern "${CRD_PATTERN}" | ${KUBECTL} apply -f -
fi


# Create a secret to include the password of the Service Principal identity created in Azure
echo; echo "Creating secret with azure credentials..."
cat <<EOF | ${KUBECTL} apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: aso-controller-settings
  namespace: azureserviceoperator-system
stringData:
  AZURE_SUBSCRIPTION_ID: "$AZURE_SUBSCRIPTION_ID"
  AZURE_TENANT_ID: "$AZURE_TENANT_ID"
  AZURE_CLIENT_ID: "$AZURE_CLIENT_ID"
  AZURE_CLIENT_SECRET: "$AZURE_CLIENT_SECRET"
EOF

# Wait for ASO deployments
echo "Wait for ASO controller manager to be ready (up to 2m) ..."
${KUBECTL} wait --for=condition=available --timeout=2m -n azureserviceoperator-system deployment azureserviceoperator-controller-manager
echo "ASO installed and the controller manager is ready."
