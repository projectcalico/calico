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

. ./utils.sh

# Use KUBECTL to access the local kind management cluster. Use KCAPZ to
# access the CAPZ cluster.
: ${KUBECTL:=./bin/kubectl}
: ${KCAPZ:="${KUBECTL} --kubeconfig=./kubeconfig"}

: ${PRODUCT:=calico}
: ${RELEASE_STREAM:="master"} # Default to master
: ${HASH_RELEASE:="false"} # Set to true to use hash release

: "${AZ_KUBE_VERSION:?Environment variable empty or not defined.}"

echo Settings:
echo '  PRODUCT='${PRODUCT}
echo '  RELEASE_STREAM='${RELEASE_STREAM}
echo '  HASH_RELEASE='${HASH_RELEASE}

if [ ${PRODUCT} == 'calient' ]; then
    # Verify if the required variables are set for Calico EE
    : "${GCR_IO_PULL_SECRET:?Environment variable empty or not defined.}"
    : "${TSEE_TEST_LICENSE:?Environment variable empty or not defined.}"
fi

SCRIPT_CURRENT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P )"
LOCAL_MANIFESTS_DIR="${SCRIPT_CURRENT_DIR}/../../../../manifests"

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
    # Check release url and installation scripts
    echo "Set release base url ${RELEASE_BASE_URL}"
    sed -i "s,export RELEASE_BASE_URL.*,export RELEASE_BASE_URL=\"${RELEASE_BASE_URL}\"," ./export-env.sh
fi

# Create a storage class and persistent volume for Calico Enterprise.
if [ ${PRODUCT} == 'calient' ]; then
    ${KCAPZ} create -f ./EE/storage-class-azure-file.yaml
    ${KCAPZ} create -f ./EE/persistent-volume.yaml
fi

# Install Calico on Linux nodes
if [[ ${RELEASE_STREAM} == 'local' ]]; then
    # Use local manifests
    ${KCAPZ} create -f ${LOCAL_MANIFESTS_DIR}/operator-crds.yaml
    ${KCAPZ} create -f ${LOCAL_MANIFESTS_DIR}/tigera-operator.yaml
else
    # Use release url
    echo "Set release base url ${RELEASE_BASE_URL}"
    sed -i "s,export RELEASE_BASE_URL.*,export RELEASE_BASE_URL=\"${RELEASE_BASE_URL}\"," ./export-env.sh
    curl -sSf -L --retry 5 ${RELEASE_BASE_URL}/manifests/operator-crds.yaml -o operator-crds.yaml
    curl -sSf -L --retry 5 ${RELEASE_BASE_URL}/manifests/tigera-operator.yaml -o tigera-operator.yaml
    ${KCAPZ} create -f ./operator-crds.yaml
    ${KCAPZ} create -f ./tigera-operator.yaml
fi

if [[ ${PRODUCT} == 'calient' ]]; then
    # Install prometheus operator
    if [[ ${RELEASE_STREAM} == 'local' ]]; then
        ${KCAPZ} create -f ${LOCAL_MANIFESTS_DIR}/tigera-prometheus-operator.yaml
    else
        curl -sSf -L --retry 5 ${RELEASE_BASE_URL}/manifests/tigera-prometheus-operator.yaml -o tigera-prometheus-operator.yaml
        ${KCAPZ} create -f ./tigera-prometheus-operator.yaml
    fi

    # Install pull secret.
    ${KCAPZ} create secret generic tigera-pull-secret \
      --type=kubernetes.io/dockerconfigjson -n tigera-operator \
      --from-file=.dockerconfigjson=${GCR_IO_PULL_SECRET}

    # When using an EE hash release, the operator has to have tigera-pull-secret in its imagePullSecrets.
    if [[ ${HASH_RELEASE} == 'true' ]]; then
        ${KCAPZ} patch deployment tigera-operator -n tigera-operator --patch '{"spec":{"template":{"spec":{"imagePullSecrets":[{"name":"tigera-pull-secret"}]}}}}'
    fi

    # Create custom resources
    ${KCAPZ} create -f ./EE/custom-resources.yaml

    # Install Calico EE license (after the Tigera apiserver comes up)
    echo "Wait for the Tigera apiserver to be ready..."
    timeout --foreground 600 bash -c "while ! ${KCAPZ} wait pod -l k8s-app=tigera-apiserver --for=condition=Ready -n tigera-system --timeout=30s; do sleep 5; done"
    echo "Tigera apiserver is ready, installing Calico EE license"

    retry_command 60 "${KCAPZ} create -f ${TSEE_TEST_LICENSE}"
else
    # Create custom resources
    ${KCAPZ} create -f ./OSS/custom-resources.yaml
fi

echo "Wait for Calico to be ready on Linux nodes..."
timeout --foreground 600 bash -c "while ! ${KCAPZ} wait pod -l k8s-app=calico-node --for=condition=Ready -n calico-system --timeout=30s; do sleep 5; done"
echo "Calico is ready on Linux nodes"

# Install Calico on Windows nodes

# Turn strict affinity on in the default IPAMConfig (required for Windows)
${KCAPZ} patch ipamconfig default --type merge --patch='{"spec": {"strictAffinity": true}}'

# Find out apiserver address and port and fill in 'kubernetes-services-endpoint' configmap (required for Windows)
APISERVER=$(${KCAPZ} get configmap -n kube-system kube-proxy -o yaml | awk -F'://' '/server: https:\/\// { print $2 }')
APISERVER_ADDR=$(echo ${APISERVER} | awk -F':' '{ print $1 }')
APISERVER_PORT=$(echo ${APISERVER} | awk -F':' '{ print $2 }')
${KCAPZ} apply -f - << EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: kubernetes-services-endpoint
  namespace: tigera-operator
data:
  KUBERNETES_SERVICE_HOST: "${APISERVER_ADDR}"
  KUBERNETES_SERVICE_PORT: "${APISERVER_PORT}"
EOF

# Patch installation to include required serviceCIDRs information and enable the Windows daemonset
${KCAPZ} patch installation default --type merge --patch='{"spec": {"serviceCIDRs": ["10.96.0.0/12"], "calicoNetwork": {"windowsDataplane": "HNS"}}}'

echo "Wait for Calico to be ready on Windows nodes..."
timeout --foreground 600 bash -c "while ! ${KCAPZ} wait pod -l k8s-app=calico-node-windows --for=condition=Ready -n calico-system --timeout=30s; do sleep 5; done"
echo "Calico is ready on Windows nodes"

# Create the kube-proxy-windows daemonset
echo "Install kube-proxy-windows ${AZ_KUBE_VERSION} from sig-windows-tools"
for iter in {1..5};do
    curl -sSf -L  https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/hostprocess/calico/kube-proxy/kube-proxy.yml | sed "s/KUBE_PROXY_VERSION/${AZ_KUBE_VERSION}/g" | ${KCAPZ} apply -f - && break || echo "download error: retry $iter in 5s" && sleep 5;
done;

echo "Wait for kube-proxy to be ready on Windows nodes..."
timeout --foreground 1200 bash -c "while ! ${KCAPZ} wait pod -l k8s-app=kube-proxy-windows --for=condition=Ready -n kube-system --timeout=30s; do sleep 5; done"
echo "kube-proxy is ready on Windows nodes"
