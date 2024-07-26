#!/bin/bash
# Copyright (c) 2022 Tigera, Inc. All rights reserved.
# Copyright 2020 The Kubernetes Authors.
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
: "${CLUSTER_NAME_CAPZ:?Environment variable empty or not defined.}"
: "${AZURE_LOCATION:?Environment variable empty or not defined.}"
: "${AZURE_RESOURCE_GROUP:?Environment variable empty or not defined.}"
: "${WINDOWS_SERVER_VERSION:?Environment variable empty or not defined.}"
: "${KUBE_VERSION:?Environment variable empty or not defined.}"
: "${CLUSTER_API_VERSION:?Environment variable empty or not defined.}"
: "${AZURE_PROVIDER_VERSION:?Environment variable empty or not defined.}"

: "${AZURE_SUBSCRIPTION_ID:?Environment variable empty or not defined.}"
: "${AZURE_TENANT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_SECRET:?Environment variable empty or not defined.}"

# Set and export VM types.
: "${AZURE_CONTROL_PLANE_MACHINE_TYPE:=Standard_D2s_v3}"
: "${AZURE_NODE_MACHINE_TYPE:=Standard_D2s_v3}"
: "${SEMAPHORE:=false}"
export AZURE_CONTROL_PLANE_MACHINE_TYPE
export AZURE_NODE_MACHINE_TYPE

# Number of Linux node is same as number of Windows nodes
: ${WIN_NODE_COUNT:=2}
TOTAL_NODES=$((WIN_NODE_COUNT*2+1))
SEMAPHORE="${SEMAPHORE:="false"}"
SUFFIX=""

echo Settings:
echo '  CLUSTER_NAME_CAPZ='${CLUSTER_NAME_CAPZ}
echo '  AZURE_LOCATION='${AZURE_LOCATION}
echo '  KUBE_VERSION='${KUBE_VERSION}
echo '  WIN_NODE_COUNT='${WIN_NODE_COUNT}

# Utilities
: ${KIND:=./bin/kind}
: ${KUBECTL:=./bin/kubectl}
: ${CLUSTERCTL:=./bin/clusterctl}
: ${KCAPZ:="${KUBECTL} --kubeconfig=./kubeconfig"}

# Base64 encode the variables
if [[ $SEMAPHORE == "false" ]]; then
  AZURE_SUBSCRIPTION_ID_B64="$(echo -n "$AZURE_SUBSCRIPTION_ID" | base64 | tr -d '\n')"
  AZURE_TENANT_ID_B64="$(echo -n "$AZURE_TENANT_ID" | base64 | tr -d '\n')"
  AZURE_CLIENT_ID_B64="$(echo -n "$AZURE_CLIENT_ID" | base64 | tr -d '\n')"
  AZURE_CLIENT_SECRET_B64="$(echo -n "$AZURE_CLIENT_SECRET" | base64 | tr -d '\n')"
else
  export SUFFIX="-${RAND}"
fi



# Settings needed for AzureClusterIdentity used by the AzureCluster
export AZURE_CLUSTER_IDENTITY_SECRET_NAME="cluster-identity-secret"
export CLUSTER_IDENTITY_NAME="cluster-identity"
export AZURE_CLUSTER_IDENTITY_SECRET_NAMESPACE="default"

export EXP_MACHINE_POOL=true
export EXP_AKS=true

# Create management cluster
${KIND} create cluster --image kindest/node:${KUBE_VERSION} --name kind${SUFFIX}
${KUBECTL} wait node kind${SUFFIX}-control-plane --for=condition=ready --timeout=90s

sleep 30

# Initialize cluster

# Create a secret to include the password of the Service Principal identity created in Azure
# This secret will be referenced by the AzureClusterIdentity used by the AzureCluster
${KUBECTL} create secret generic "${AZURE_CLUSTER_IDENTITY_SECRET_NAME}" --from-literal=clientSecret="${AZURE_CLIENT_SECRET}"

# Finally, initialize the management cluster
${CLUSTERCTL} init --infrastructure azure:${AZURE_PROVIDER_VERSION} --core cluster-api:${CLUSTER_API_VERSION}

# Generate SSH key.
rm .sshkey* || true
SSH_KEY_FILE=${SSH_KEY_FILE:-""}
if [ -z "$SSH_KEY_FILE" ]; then
    SSH_KEY_FILE=.sshkey
    rm -f "${SSH_KEY_FILE}" 2>/dev/null
    ssh-keygen -t rsa -b 2048 -f "${SSH_KEY_FILE}" -N '' -C "" 1>/dev/null
    echo "Machine SSH key generated in ${SSH_KEY_FILE}"
fi

AZURE_SSH_PUBLIC_KEY_B64=$(base64 "${SSH_KEY_FILE}.pub" | tr -d '\r\n')
export AZURE_SSH_PUBLIC_KEY_B64

# Windows sets the public key via cloudbase-init which take the raw text as input
AZURE_SSH_PUBLIC_KEY=$(< "${SSH_KEY_FILE}.pub" tr -d '\r\n')
export AZURE_SSH_PUBLIC_KEY

${CLUSTERCTL} generate cluster ${CLUSTER_NAME_CAPZ} \
  --kubernetes-version ${KUBE_VERSION} \
  --control-plane-machine-count=1 \
  --worker-machine-count=${WIN_NODE_COUNT}\
  --flavor machinepool-windows \
  > win-capz.yaml

retry_command 900 "${KUBECTL} apply -f win-capz.yaml"

# Wait for CAPZ deployments
${KUBECTL} wait --for=condition=Available --timeout=5m -n capz-system deployment -l cluster.x-k8s.io/provider=infrastructure-azure

# Wait for the kubeconfig to become available.
timeout --foreground 900 bash -c "while ! ${KUBECTL} get secrets | grep ${CLUSTER_NAME_CAPZ}-kubeconfig; do sleep 5; done"
# Get kubeconfig and store it locally.
${CLUSTERCTL} get kubeconfig ${CLUSTER_NAME_CAPZ} > ./kubeconfig
timeout --foreground 900 bash -c "while ! ${KUBECTL} --kubeconfig=./kubeconfig get nodes | grep control-plane; do sleep 5; done"
echo "Cluster config is ready at ./kubeconfig. Run \'${KUBECTL} --kubeconfig=./kubeconfig ...\' to work with the new target cluster"
echo "Waiting for ${TOTAL_NODES} nodes to have been provisioned..."
timeout --foreground 900 bash -c "while ! ${KCAPZ} get nodes | grep ${KUBE_VERSION} | wc -l | grep ${TOTAL_NODES}; do sleep 5; done"
echo "Seen all ${TOTAL_NODES} nodes"

# Do NOT instal Azure cloud provider (clear taint instead)
retry_command 300 "${KCAPZ} taint nodes --all node.cloudprovider.kubernetes.io/uninitialized:NoSchedule-"
# This one is a workaround for https://github.com/kubernetes-sigs/cluster-api-provider-azure/issues/3472
retry_command 300 "${KCAPZ} taint nodes --selector=!node-role.kubernetes.io/control-plane node.cluster.x-k8s.io/uninitialized:NoSchedule-"

echo "Done creating cluster"

ID0=`${KCAPZ} get node -o wide | grep win-p-win000000 | awk '{print $6}' | awk -F '.' '{print $4}'`
echo "ID0: $ID0"
if [[ ${WIN_NODE_COUNT} -gt 1 ]]; then
  ID1=`${KCAPZ} get node -o wide | grep win-p-win000001 | awk '{print $6}' | awk -F '.' '{print $4}'`
  echo "ID1:$ID1"
fi
