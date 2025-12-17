#!/bin/bash
# Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.
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

. ../util/utils.sh
. ./export-env.sh

# Trap to show pod status on failure for debugging
trap 'exit_code=$?; if [ $exit_code -ne 0 ]; then echo ""; echo "========================================"; echo "Script failed! Showing pod status for debugging:"; echo "========================================"; ./bin/kubectl get pod -A -o wide --kubeconfig=./kubeconfig 2>/dev/null || true; fi; exit $exit_code' EXIT

# Use kubectl with kubeconfig from install-kubeadm.sh
: ${KUBECTL:=./bin/kubectl}

# Use the kubeconfig that was copied from master node
KUBECONFIG_FILE="./kubeconfig"
if [ ! -f "${KUBECONFIG_FILE}" ]; then
  echo "ERROR: kubeconfig file not found at ${KUBECONFIG_FILE}"
  echo "Please run install-kubeadm.sh first to set up the cluster and copy kubeconfig"
  exit 1
fi

export KUBECONFIG="${KUBECONFIG_FILE}"
echo "Using kubeconfig from: ${KUBECONFIG_FILE}"

: ${PRODUCT:=calient}
: ${RELEASE_STREAM:="master"} # Default to master
: ${HASH_RELEASE:="true"} # Set to true to use hash release

: "${KUBE_VERSION:?Environment variable empty or not defined.}"

echo Settings:
echo '  PRODUCT='${PRODUCT}
echo '  RELEASE_STREAM='${RELEASE_STREAM}
echo '  HASH_RELEASE='${HASH_RELEASE}
echo '  KUBE_VERSION='${KUBE_VERSION}

if [ ${PRODUCT} == 'calient' ]; then
    # Verify if the required variables are set for Calico EE
    : "${GCR_IO_PULL_SECRET:?Environment variable empty or not defined.}"
    : "${TSEE_TEST_LICENSE:?Environment variable empty or not defined.}"
    echo '  GCR_IO_PULL_SECRET='${GCR_IO_PULL_SECRET}
    echo '  TSEE_TEST_LICENSE='${TSEE_TEST_LICENSE}
fi

SCRIPT_CURRENT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P )"
LOCAL_MANIFESTS_DIR="${SCRIPT_CURRENT_DIR}/../../../manifests"

if [ ${PRODUCT} == 'calient' ]; then
    RELEASE_BASE_URL="https://downloads.tigera.io/ee/${RELEASE_STREAM}"
else
    RELEASE_BASE_URL="https://raw.githubusercontent.com/projectcalico/calico/${RELEASE_STREAM}"
fi

if [ ${HASH_RELEASE} == 'true' ]; then
    if [ -z ${RELEASE_STREAM} ]; then
	    echo "RELEASE_STREAM not set for HASH release"
	    exit 1
    fi
    if [ ${PRODUCT} == 'calient' ]; then
      URL_HASH="https://latest-cnx.docs.eng.tigera.net/${RELEASE_STREAM}.txt"
    else
      URL_HASH="https://latest-os.docs.eng.tigera.net/${RELEASE_STREAM}.txt"
    fi
    RELEASE_BASE_URL=$(curl -sS ${URL_HASH})
fi

if [[ ${RELEASE_STREAM} != 'local' ]]; then
    # Check release url
    echo '  RELEASE_BASE_URL='${RELEASE_BASE_URL}
fi

# Create a storage class and persistent volume for Calico Enterprise.
if [ ${PRODUCT} == 'calient' ]; then
    ${KUBECTL} create -f ./EE/storage-class-azure-file.yaml
    ${KUBECTL} create -f ./EE/persistent-volume.yaml
fi

# Install Calico on Linux nodes
if [[ ${RELEASE_STREAM} == 'local' ]]; then
    # Use local manifests
    ${KUBECTL} create -f ${LOCAL_MANIFESTS_DIR}/operator-crds.yaml
    ${KUBECTL} create -f ${LOCAL_MANIFESTS_DIR}/tigera-operator.yaml
else
    # Download and install from release
    echo "Downloading Calico manifests from ${RELEASE_BASE_URL}"
    curl -sSf -L --retry 5 ${RELEASE_BASE_URL}/manifests/operator-crds.yaml -o operator-crds.yaml
    curl -sSf -L --retry 5 ${RELEASE_BASE_URL}/manifests/tigera-operator.yaml -o tigera-operator.yaml
    ${KUBECTL} create -f ./operator-crds.yaml
    ${KUBECTL} create -f ./tigera-operator.yaml
fi

if [[ ${PRODUCT} == 'calient' ]]; then
    # Install prometheus operator
    if [[ ${RELEASE_STREAM} == 'local' ]]; then
        ${KUBECTL} create -f ${LOCAL_MANIFESTS_DIR}/tigera-prometheus-operator.yaml
    else
        curl -sSf -L --retry 5 ${RELEASE_BASE_URL}/manifests/tigera-prometheus-operator.yaml -o tigera-prometheus-operator.yaml
        ${KUBECTL} create -f ./tigera-prometheus-operator.yaml
    fi

    # Install pull secret.
    ${KUBECTL} create secret generic tigera-pull-secret \
      --type=kubernetes.io/dockerconfigjson -n tigera-operator \
      --from-file=.dockerconfigjson=${GCR_IO_PULL_SECRET}

    # When using an EE hash release, the operator has to have tigera-pull-secret in its imagePullSecrets.
    if [[ ${HASH_RELEASE} == 'true' ]]; then
        ${KUBECTL} patch deployment tigera-operator -n tigera-operator --patch '{"spec":{"template":{"spec":{"imagePullSecrets":[{"name":"tigera-pull-secret"}]}}}}'
    fi

    # Create custom resources
    ${KUBECTL} create -f ./EE/custom-resources.yaml

    # Install Calico EE license (after the Calico apiserver comes up)
    echo "Wait for the Calico apiserver to be ready..."
    timeout --foreground 300 bash -c "while ! ${KUBECTL} wait pod -l k8s-app=calico-apiserver --for=condition=Ready -n calico-system --timeout=30s; do sleep 5; done"
    echo "Calico apiserver is ready, installing Calico EE license"

    retry_command 60 "${KUBECTL} create -f ${TSEE_TEST_LICENSE}"
else
    # Create custom resources
    ${KUBECTL} create -f ./OSS/custom-resources.yaml
fi

echo "Wait for Calico to be ready on Linux nodes..."
timeout --foreground 300 bash -c "while ! ${KUBECTL} wait pod -l k8s-app=calico-node --for=condition=Ready -n calico-system --timeout=30s; do sleep 5; done"
echo "Calico is ready on Linux nodes"

# Install Calico on Windows nodes
echo ""
echo "=========================================="
echo "Installing Calico on Windows nodes..."
echo "=========================================="

echo "Enabling strict affinity in IPAMConfig (required for Windows)..."
${KUBECTL} patch ipamconfig default --type merge --patch='{"spec": {"strictAffinity": true}}'

echo "Creating kubernetes-services-endpoint ConfigMap..."
APISERVER=$(${KUBECTL} get configmap -n kube-system kube-proxy -o yaml | awk -F'://' '/server: https:\/\// { print $2 }')
APISERVER_ADDR=$(echo ${APISERVER} | awk -F':' '{ print $1 }')
APISERVER_PORT=$(echo ${APISERVER} | awk -F':' '{ print $2 }')
${KUBECTL} apply -f - << EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: kubernetes-services-endpoint
  namespace: tigera-operator
data:
  KUBERNETES_SERVICE_HOST: "${APISERVER_ADDR}"
  KUBERNETES_SERVICE_PORT: "${APISERVER_PORT}"
EOF

echo "Enabling Windows dataplane (HNS) and configuring serviceCIDRs... (already configured in custom-resources.yaml)"
# ${KUBECTL} patch installation default --type merge --patch='{"spec": {"serviceCIDRs": ["10.96.0.0/12"], "calicoNetwork": {"windowsDataplane": "HNS"}}}'

echo "Configuring Windows CNI paths to match containerd configuration... (already configured in custom-resources.yaml)"
# For some reason, patch not working with this.
#${KUBECTL} patch installation default --type merge --patch='{"spec": {"windowsNodes": {"cniBinDir": "/Program Files/containerd/cni/bin", "cniConfigDir": "/Program Files/containerd/cni/conf", "cniLogDir": "/var/log/calico/cni"}}}'

echo "Wait for Calico to be ready on Windows nodes..."
timeout --foreground 600 bash -c "while ! ${KUBECTL} wait pod -l k8s-app=calico-node-windows --for=condition=Ready -n calico-system --timeout=30s; do sleep 5; done"
echo "Calico is ready on Windows nodes"

# Create the kube-proxy-windows daemonset
echo "Install kube-proxy-windows ${KUBE_VERSION} from sig-windows-tools"
for iter in {1..5};do
    curl -sSf -L  https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/hostprocess/calico/kube-proxy/kube-proxy.yml | sed "s/KUBE_PROXY_VERSION/${KUBE_VERSION}/g" | ${KUBECTL} apply -f - && break || echo "download error: retry $iter in 5s" && sleep 5;
done;

echo "Wait for kube-proxy to be ready on Windows nodes..."
timeout --foreground 1200 bash -c "while ! ${KUBECTL} wait pod -l k8s-app=kube-proxy-windows --for=condition=Ready -n kube-system --timeout=30s; do sleep 5; done"
echo "kube-proxy is ready on Windows nodes"

echo "Wait for calico-node-windows pods to be ready..."
timeout --foreground 600 bash -c "while ! ${KUBECTL} wait pod -l k8s-app=calico-node-windows --for=condition=Ready -n calico-system --timeout=30s; do sleep 5; done"
echo "calico-node-windows pods are ready"

if [[ ${PRODUCT} == 'calient' ]]; then
    echo "Wait for fluentd-node-windows pods to be ready..."
    echo "It takes a long time for fluentd-node-windows pods to pull images and start.Sleeping for 8 minutes..."
    sleep 480
    timeout --foreground 300 bash -c "while ! ${KUBECTL} wait pod -l k8s-app=fluentd-node-windows --for=condition=Ready -n tigera-fluentd --timeout=30s; do sleep 5; done"
    echo "fluentd-node-windows pods are ready"
fi

echo ""
echo "=========================================="
echo "Calico installation completed successfully!"
echo "=========================================="
${KUBECTL} get nodes -o wide
echo ""
echo "Calico pods:"
${KUBECTL} get pods -n calico-system -o wide
