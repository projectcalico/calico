#!/bin/bash
# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

set -e

. ./utils.sh

. ./vmss.sh info

: ${KUBECTL:=./bin/kubectl}
: ${GOMPLATE:=./bin/gomplate}
: ${BACKEND:?Error: BACKEND is not set}

function setup_minikube_cluster() {
  #https://github.com/kubernetes/minikube/issues/14364

  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ./create-minikube-cluster.sh winfv@${LINUX_EIP}:/home/winfv/
  ${MASTER_CONNECT_COMMAND} sudo chmod +x /home/winfv/create-minikube-cluster.sh
  ${MASTER_CONNECT_COMMAND} bash /home/winfv/create-minikube-cluster.sh ${LINUX_PIP}

  APISERVER_PORT=$(${MASTER_CONNECT_COMMAND} cat /home/winfv/port_info)
  export APISERVER_PORT

    #create etcd manually with http protocol
  LOCAL_IP_ENV=${LINUX_PIP}
  ETCD_CONTAINER=quay.io/coreos/etcd:v3.4.6
  ${MASTER_CONNECT_COMMAND} docker run --detach -p 2389:2389 --name calico-etcd ${ETCD_CONTAINER}  etcd --advertise-client-urls "http://${LOCAL_IP_ENV}:2389,http://127.0.0.1:2389,http://${LOCAL_IP_ENV}:8001,http://127.0.0.1:8001" --listen-client-urls "http://0.0.0.0:2389,http://0.0.0.0:8001"

  echo
  ${MASTER_CONNECT_COMMAND} docker ps -a

  echo "Setup linux is done."
  echo
  echo
}

function copy_files_from_linux() {
  mkdir -p ./windows/minikube
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${LINUX_EIP}:/home/winfv/.minikube/ca.crt ./windows/minikube
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${LINUX_EIP}:/home/winfv/.minikube/profiles/minikube/client.crt ./windows/minikube
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${LINUX_EIP}:/home/winfv/.minikube/profiles/minikube/client.key ./windows/minikube
}

function prepare_and_copy_windows_dir () {
  ${GOMPLATE} --file ./run-fv-cni-plugin.ps1 --out ./windows/run-fv.ps1
  ${GOMPLATE} --file ./config-minikube --out ./windows/config

  # Copy local windows directory to Windows node.
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -r ./windows winfv@${WINDOWS_EIP}:c:\\k\\
}

function prepare_windows_node() {
  ${WINDOWS_CONNECT_COMMAND} c:\\k\\enable-containers-with-reboot.ps1
  sleep 10
  retry_command 60 "${WINDOWS_CONNECT_COMMAND} Get-HnsNetwork"

  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\install-containerd.ps1 -ContainerDVersion ${CONTAINERD_VERSION}"
  echo
}

function create_l2bridge_network() {
  # Create external network will cause ssh session to hang.
  # Use timeout and ignore error state to make sure the script will 
  # keep running.
  set +e
  timeout -s SIGTERM 20s ${WINDOWS_CONNECT_COMMAND} "c:\\k\\create-network.ps1 -Backend l2bridge"
  set -e
}

function create_overlay_network() {
  set +e
  timeout -s SIGTERM 20s ${WINDOWS_CONNECT_COMMAND} "c:\\k\\create-network.ps1 -Backend overlay"
  set -e
}

function run_fv_l2bridge() {
  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\run-fv.ps1 -Backend l2bridge"
  echo
}

function run_fv_overlay() {
  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\run-fv.ps1 -Backend overlay"
  echo
}

setup_minikube_cluster
copy_files_from_linux
prepare_and_copy_windows_dir
prepare_windows_node

if [[ "$BACKEND" == "overlay" ]]; then
  create_overlay_network
  run_fv_overlay
elif [[ "$BACKEND" = "l2bridge" ]]; then
  create_l2bridge_network
  run_fv_l2bridge
else
  echo "Invalid network backend paramenter $BACKEND provided"
  exit -1
fi

# Copy report directory from windows.
rm -r ./report || true
scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -r winfv@${WINDOWS_EIP}:c:\\k\\report .

echo "All done."