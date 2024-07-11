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

# This script sets up a k8s cluster with one Linux node and one Windows node and run windows FV test.
# Usage - OS Felix fv, following variables need to be set
#         AZURE_SUBSCRIPTION_ID
#         AZURE_TENANT_ID
#         AZURE_CLIENT_ID
#         AZURE_CLIENT_SECRET
#         FV_TYPE
#

set -o errexit
set -o nounset
set -o pipefail

GIT_VERSION=$(git describe --tags --dirty --long --always --abbrev=12)
CALICO_HOME=$(cd $(dirname $0)/../../../; pwd)
CAPZ_LOCATION=$CALICO_HOME/process/testing/winfv/capz
KUBECONFIG=$CALICO_HOME/process/testing/winfv/capz/kubeconfig
SEMAPHORE="${SEMAPHORE:="false"}"
export RAND=$(tr -dc a-z0-9 </dev/urandom | head -c 4; echo)
export WIN_NODE_COUNT=1

function shutdown_cluster(){
  EXIT_CODE=$?
  make -C $CAPZ_LOCATION delete-cluster
  # Clear trap
  trap - EXIT
  exit $EXIT_CODE
}

trap shutdown_cluster EXIT

function prepare_env(){
# Set up capz variables
  if [[ $FV_TYPE != "cni-plugin" ]] && [[ $FV_TYPE != "calico-felix" ]]; then
    echo "FV_TYPE not set or invalid"
    exit 1
  fi

  if [[ $SEMAPHORE == "true" ]]; then
    export CLUSTER_NAME_CAPZ="${USER}-capz-win-${RAND}"
  fi

  . $CALICO_HOME/process/testing/winfv/capz/export-env.sh
}

function start_cluster(){
  # Use EXIT_CODE to bypass errexit and capture more information about a possible failure here
    EXIT_CODE=0
    make -C $CAPZ_LOCATION create-cluster || EXIT_CODE=$?
    if [[ $EXIT_CODE -ne 0 ]]; then
        echo "failed to create CAPZ cluster"
        exit $EXIT_CODE
    fi
    # Use EXIT_CODE to bypass errexit and capture more information about a possible failure here
    EXIT_CODE=0
    make -C $CAPZ_LOCATION install-calico RELEASE_STREAM=master HASH_RELEASE=true PRODUCT=calico || EXIT_CODE=$?
    if [[ $EXIT_CODE -ne 0 ]]; then
        echo "failed to install Calico"
        ${KCAPZ} describe tigerastatus
        ${KCAPZ} get tigerastatus -o yaml
        exit $EXIT_CODE
    fi
  WIN_NODE=$(kubectl get nodes -o wide -l kubernetes.io/os=windows --no-headers --kubeconfig $KUBECONFIG | awk -v OFS='\t\t' '{print $6}')
  export WIN_NODE_IP=${WIN_NODE: -1}
  export LINUX_NODE=$(kubectl get nodes -l kubernetes.io/os=linux,'!node-role.kubernetes.io/control-plane' -o wide --no-headers --kubeconfig $KUBECONFIG | awk -v OFS='\t\t' '{print $6}')
}

function upload_calico_images(){
  $CAPZ_LOCATION/scp-to-node.sh $WIN_NODE_IP $KUBECONFIG c:\\k\\config
  $CAPZ_LOCATION/scp-to-node.sh $WIN_NODE_IP $CALICO_HOME/node/dist/windows/$CALICO_NODE_IMAGE c:\\calico-node-windows.tar
  $CAPZ_LOCATION/scp-to-node.sh $WIN_NODE_IP $CALICO_HOME/cni-plugin/dist/windows/$CALICO_CNI_IMAGE c:\\calico-cni-plugin-windows.tar
  #Imports calico-node-windows image from locally build image
  $CAPZ_LOCATION/ssh-node.sh $WIN_NODE_IP 'ctr --namespace k8s.io images import --base-name calico/node-windows c:\calico-node-windows.tar --all-platforms' > output
  $CAPZ_LOCATION/ssh-node.sh $WIN_NODE_IP 'ctr --namespace k8s.io images import --base-name calico/cni-windows c:\calico-cni-plugin-windows.tar --all-platforms' > output
}

function upload_fv(){
  if [[ $FV_TYPE == "cni-plugin" ]]; then
    $CAPZ_LOCATION/scp-to-node.sh $WIN_NODE_IP $CALICO_HOME/process/testing/winfv/run-cni-fv.ps1 c:\\run-cni-fv.ps1
    $CAPZ_LOCATION/scp-to-node.sh $WIN_NODE_IP $CALICO_HOME/cni-plugin/bin/windows/win-fv.exe c:\\k\\win-cni-fv.exe
  elif [[ $FV_TYPE == "calico-felix" ]]; then
    $CAPZ_LOCATION/scp-to-node.sh $WIN_NODE_IP $CALICO_HOME/process/testing/winfv/run-felix-fv.ps1 c:\\run-felix-fv.ps1
    $CAPZ_LOCATION/scp-to-node.sh $WIN_NODE_IP $CALICO_HOME/felix/fv/win-fv.exe c:\\k\\win-felix-fv.exe
  fi
}

function prepare_windows_images(){
  make -C $CALICO_HOME/node image-windows WINDOWS_IMAGE=node-windows
  make -C $CALICO_HOME/cni-plugin image-windows WINDOWS_IMAGE=cni-windows

  if [[ $WINDOWS_SERVER_VERSION == "windows-2022" ]]; then
    CALICO_NODE_IMAGE="node-windows-$GIT_VERSION-ltsc2022.tar"
    CALICO_CNI_IMAGE="cni-windows-$GIT_VERSION-ltsc2022.tar"
  else
    CALICO_NODE_IMAGE="node-windows-$GIT_VERSION-1809.tar"
    CALICO_CNI_IMAGE="cni-windows-$GIT_VERSION-1809.tar"
  fi
}

function prepare_fv(){
  if [[ $FV_TYPE == "cni-plugin" ]]; then
    make -C $CALICO_HOME/cni-plugin bin/windows/win-fv.exe
    FV_RUN_CNI=$CALICO_HOME/process/testing/winfv/run-cni-fv.ps1
    cp $CALICO_HOME/process/testing/winfv/run-fv-cni-plugin.ps1 $FV_RUN_CNI
    sed -i "s?<your kube version>?${KUBE_VERSION}?g" $FV_RUN_CNI
    sed -i "s?<your linux pip>?${LINUX_NODE}?g" $FV_RUN_CNI
    sed -i "s?<your os version>?${WINDOWS_SERVER_VERSION}?g" $FV_RUN_CNI
    sed -i "s?<your container runtime>?containerd?g" $FV_RUN_CNI
    sed -i "s?<your containerd version>?${CONTAINERD_VERSION}?g" $FV_RUN_CNI
    sed -i "s?win-fv.exe?win-cni-fv.exe?g" $FV_RUN_CNI
  elif [[ $FV_TYPE == "calico-felix" ]]; then
    make -C $CALICO_HOME/felix fv/win-fv.exe
    FV_RUN_FELIX=$CALICO_HOME/process/testing/winfv/run-felix-fv.ps1
    cp $CALICO_HOME/process/testing/winfv/run-fv-full.ps1 $FV_RUN_FELIX
    sed -i "s?<your kube version>?${KUBE_VERSION}?g" $FV_RUN_FELIX
    sed -i "s?<your linux pip>?${LINUX_NODE}?g" $FV_RUN_FELIX
    sed -i "s?<your os version>?${WINDOWS_SERVER_VERSION}?g" $FV_RUN_FELIX
    sed -i "s?<your container runtime>?containerd?g" $FV_RUN_FELIX
    sed -i "s?<your containerd version>?${CONTAINERD_VERSION}?g" $FV_RUN_FELIX
    sed -i "s?<your fv type>?tigera-felix?g" $FV_RUN_FELIX
    sed -i "s?<your fv provisioner>?capz?g" $FV_RUN_FELIX
    sed -i "s?win-fv.exe?win-felix-fv.exe?g" $FV_RUN_FELIX
  fi

  upload_fv ${WIN_NODE_IP}
}

function wait_for_nodes(){
  #Wait for calico-node-windows daemon set to update
  sleep 30
  for i in `seq 1 30`; do
    if [[ `kubectl get ds calico-node-windows -n calico-system --no-headers --kubeconfig $KUBECONFIG | awk -v OFS='\t\t' '{print $6}'` = "$WIN_NODE_COUNT" ]] ; then
      echo "Calico Node Windows is ready"
      return
    fi
    echo "Waiting for Calico Node Windows to update"
    sleep 30
  done
  echo "Node windows did not start"
  exit 1
}

function update_windows_node(){
  upload_calico_images
  kubectl annotate ds -n calico-system calico-node-windows unsupported.operator.tigera.io/ignore="true" --kubeconfig $KUBECONFIG
  kubectl patch ds -n calico-system calico-node-windows --patch-file $CALICO_HOME/process/testing/winfv/calico-node-windows.yaml  --kubeconfig $KUBECONFIG
}

function start_test_infra(){
  $CALICO_HOME/process/testing/winfv/infra/setup.sh $KUBECONFIG

  #Wait for porter pod to be running on windows node
  for i in `seq 1 30`; do
   if [[ `kubectl -n demo get pods porter --no-headers -o custom-columns=NAMESPACE:metadata.namespace,POD:metadata.name,PodIP:status.podIP,READY-true:status.containerStatuses[*].ready --kubeconfig $KUBECONFIG | awk -v OFS='\t\t' '{print $4}'` = "true" ]] ; then
     echo "Porter is ready"
     return
   fi
   echo "Waiting for porter to be ready"
   sleep 30
  done
  echo "Porter windows did not start"
  exit 1
}

function run_windows_fv(){
  if [[ $FV_TYPE == "cni-plugin" ]]; then
    $CAPZ_LOCATION/ssh-node.sh $WIN_NODE_IP 'c:\\run-cni-fv.ps1' > output
  elif [[ $FV_TYPE == "calico-felix" ]]; then
    $CAPZ_LOCATION/ssh-node.sh $WIN_NODE_IP 'c:\\run-felix-fv.ps1' > output
  fi
}

function get_test_results(){
  $CAPZ_LOCATION/scp-from-node.sh $WIN_NODE_IP c:\\k\\report $CALICO_HOME/process/testing/winfv/
  if [[ $SEMAPHORE == "false" ]]; then
    cat $CALICO_HOME/process/testing/winfv/report/fv-test.log
  fi
}

function shutdown_cluster(){
  make -C $CAPZ_LOCATION delete-cluster
}

prepare_env
start_cluster
prepare_windows_images
update_windows_node
wait_for_nodes
prepare_fv
start_test_infra
run_windows_fv
get_test_results
shutdown_cluster
