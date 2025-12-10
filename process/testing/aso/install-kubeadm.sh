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

set -e

. ../util/utils.sh

. ./vmss.sh node-ips

: ${KUBECTL:=./bin/kubectl}
: ${GOMPLATE:=./bin/gomplate}

# Reconstruct arrays from exported string variables
# Bash arrays cannot be exported across shells, so we export them as space-separated strings
read -ra LINUX_EIPS <<< "${LINUX_EIPS_STR}"
read -ra LINUX_PIPS <<< "${LINUX_PIPS_STR}"
read -ra WINDOWS_EIPS <<< "${WINDOWS_EIPS_STR}"
read -ra WINDOWS_PIPS <<< "${WINDOWS_PIPS_STR}"

# Debug: Print available node information
echo "========================================"
echo "Node configuration loaded:"
echo "  LINUX_NODE_COUNT: ${LINUX_NODE_COUNT}"
echo "  WINDOWS_NODE_COUNT: ${WINDOWS_NODE_COUNT}"
echo "  LINUX_EIPS (count: ${#LINUX_EIPS[@]}): ${LINUX_EIPS[@]}"
echo "  LINUX_PIPS (count: ${#LINUX_PIPS[@]}): ${LINUX_PIPS[@]}"
echo "  WINDOWS_EIPS (count: ${#WINDOWS_EIPS[@]}): ${WINDOWS_EIPS[@]}"
echo "  WINDOWS_PIPS (count: ${#WINDOWS_PIPS[@]}): ${WINDOWS_PIPS[@]}"
echo "========================================"
echo


function copy_scripts_to_linux_nodes() {
  echo "Copying Linux setup scripts to all Linux nodes..."

  # Copy to all Linux nodes
  for ((i=0; i<${LINUX_NODE_COUNT}; i++)); do
    local node_num=$((i+1))
    local linux_eip="${LINUX_EIPS[$i]}"

    if [[ -z "$linux_eip" ]]; then
      echo "ERROR: Linux node ${node_num} EIP is empty!"
      return 1
    fi

    echo "Copying scripts to Linux node ${node_num} (${linux_eip})..."
    scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
      ./linux/*.sh winfv@${linux_eip}:~/ || {
      echo "ERROR: Failed to copy scripts to Linux node ${node_num}"
      return 1
    }

    echo "Scripts copied successfully to Linux node ${node_num}"
  done

  echo "All Linux scripts copied successfully!"
  echo
}

function copy_scripts_to_windows_nodes() {
  echo "Copying Windows setup scripts to all Windows nodes..."

  # Copy to all Windows nodes
  for ((i=0; i<${WINDOWS_NODE_COUNT}; i++)); do
    local node_num=$((i+1))
    local windows_eip="${WINDOWS_EIPS[$i]}"

    if [[ -z "$windows_eip" ]]; then
      echo "ERROR: Windows node ${node_num} EIP is empty!"
      return 1
    fi

    echo "Copying scripts to Windows node ${node_num} (${windows_eip})..."
    scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
      ./windows/*.ps1 winfv@${windows_eip}:c:\\k\\ || {
      echo "ERROR: Failed to copy scripts to Windows node ${node_num}"
      return 1
    }

    echo "Scripts copied successfully to Windows node ${node_num}"
  done

  echo "All Windows scripts copied successfully!"
  echo
}

function setup_kubeadm_cluster() {
  echo "Installing kubeadm and Kubernetes ${KUBE_VERSION} on Linux VM..."

  # Run prerequisites setup script
  echo "Setting up prerequisites and installing kubeadm..."
  ${MASTER_CONNECT_COMMAND} "~/setup-node.sh ${KUBE_VERSION}"

  # Initialize kubeadm cluster
  echo "Initializing Kubernetes cluster..."
  LOCAL_IP_ENV=${LINUX_PIP}
  EXTERNAL_IP_ENV=${LINUX_EIP}

  echo "Kubeadm configuration:"
  echo "  API Server Internal IP: ${LOCAL_IP_ENV}"
  echo "  API Server External IP: ${EXTERNAL_IP_ENV}"
  echo "  Pod Network CIDR: 192.168.0.0/16"
  echo "  Service CIDR: 10.96.0.0/12"

  ${MASTER_CONNECT_COMMAND} "~/init-cluster.sh ${LOCAL_IP_ENV} 192.168.0.0/16 10.96.0.0/12 ${EXTERNAL_IP_ENV}"

  # Get the API server port (default is 6443 for kubeadm)
  APISERVER_PORT=6443
  export APISERVER_PORT

  # Note: The node will be in NotReady state until a CNI plugin is installed
  # This is expected behavior for a fresh kubeadm cluster
  echo "Waiting for API server to be responsive..."
  ${MASTER_CONNECT_COMMAND} "kubectl wait --for=condition=Ready --timeout=60s pod -n kube-system -l component=kube-apiserver || true"

  # Verify cluster is accessible
  echo "Verifying cluster accessibility..."
  ${MASTER_CONNECT_COMMAND} "kubectl cluster-info"

  # Remove control plane taints to allow scheduling pods on master
  echo "Removing control plane taints..."
  ${MASTER_CONNECT_COMMAND} "kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true"

  echo
  echo "Kubernetes cluster info:"
  ${MASTER_CONNECT_COMMAND} kubectl get nodes -o wide

  # Save the join command for Windows worker node
  echo "Generating kubeadm join command for Windows node..."
  ${MASTER_CONNECT_COMMAND} "kubeadm token create --print-join-command" > /tmp/kubeadm_join_command.txt
  KUBEADM_JOIN_COMMAND=$(cat /tmp/kubeadm_join_command.txt)
  export KUBEADM_JOIN_COMMAND
  echo "Join command saved: ${KUBEADM_JOIN_COMMAND}"

  # Copy kubeconfig to local directory
  echo "Copying kubeconfig from master node..."
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
    winfv@${LINUX_EIP}:/home/winfv/.kube/config ./kubeconfig

  # Fix the API server address in kubeconfig - replace internal IP with external IP
  echo "Updating API server address in kubeconfig to use external IP ${LINUX_EIP}..."
  INTERNAL_API_SERVER=$(grep 'server:' ./kubeconfig | awk '{print $2}')
  echo "  Original API server address: ${INTERNAL_API_SERVER}"

  # Extract port from the original server URL
  API_PORT=$(echo ${INTERNAL_API_SERVER} | sed -n 's/.*:\([0-9]*\)$/\1/p')
  if [[ -z "${API_PORT}" ]]; then
    API_PORT="6443"  # Default Kubernetes API port
  fi

  NEW_API_SERVER="https://${LINUX_EIP}:${API_PORT}"
  echo "  New API server address: ${NEW_API_SERVER}"

  # Update the kubeconfig with the external IP
  sed -i "s|${INTERNAL_API_SERVER}|${NEW_API_SERVER}|g" ./kubeconfig

  echo "Kubeconfig saved to ./kubeconfig with external API server address"

  echo "Kubernetes cluster setup completed successfully!"
}

function join_linux_worker_nodes() {
  echo "Checking for additional Linux worker nodes to join..."

  if [[ ${LINUX_NODE_COUNT} -le 1 ]]; then
    echo "Only one Linux node (control-plane), no additional workers to join"
    return 0
  fi

  echo "Joining ${LINUX_NODE_COUNT} - 1 additional Linux worker node(s) to the cluster..."

  # Loop through Linux nodes starting from index 1 (node 2)
  for ((i=1; i<${LINUX_NODE_COUNT}; i++)); do
    local node_num=$((i+1))
    local linux_eip="${LINUX_EIPS[$i]}"

    if [[ -z "$linux_eip" ]]; then
      echo "ERROR: Linux node ${node_num} EIP is empty!"
      return 1
    fi

    # Get the connect command for this node
    local connect_var="LINUX_NODE_${i}_CONNECT"
    local linux_connect_command="${!connect_var}"

    echo "====================================="
    echo "Joining Linux Node ${node_num} (${linux_eip}) as worker"
    echo "====================================="

    # Install prerequisites and kubeadm on worker node
    echo "Installing kubeadm, kubelet, and kubectl on Linux worker node ${node_num}..."
    ${linux_connect_command} "~/setup-node.sh ${KUBE_VERSION}"

    # Join the node to the cluster
    echo "Joining Linux worker node ${node_num} to the cluster..."
    echo "Using join command: ${KUBEADM_JOIN_COMMAND}"

    if ! ${linux_connect_command} "~/join-worker.sh ${KUBEADM_JOIN_COMMAND}"; then
      echo "ERROR: Failed to join Linux node ${node_num} to the cluster"
      return 1
    fi

    echo "Linux worker node ${node_num} joined successfully!"
    echo
  done

  echo "All Linux worker nodes joined successfully!"
  ${MASTER_CONNECT_COMMAND} kubectl get nodes -o wide
}

function join_windows_worker_node() {
  local windows_eip="$1"
  local windows_pip="$2"
  local node_index="$3"  # Optional, for display purposes

  if [[ -z "$windows_eip" ]]; then
    echo "ERROR: No Windows node EIP provided to join_windows_worker_node"
    return 1
  fi

  if [[ -z "$windows_pip" ]]; then
    echo "ERROR: No Windows node PIP provided to join_windows_worker_node"
    return 1
  fi

  local display_name="${node_index:-$windows_eip}"
  echo "====================================="
  echo "Joining Windows Node ${display_name} (${windows_eip})"
  echo "====================================="

  local windows_connect_command="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 winfv@${windows_eip} powershell"

  # Install kubeadm on Windows node
  echo "Installing kubeadm on Windows node ${display_name}..."
  ${windows_connect_command} "powershell -ExecutionPolicy Bypass -File c:\\k\\install-kubeadm.ps1 -K8sVersion ${KUBE_VERSION}"

  # Extract just the arguments after "kubeadm join"
  JOIN_ARGS=$(echo "${KUBEADM_JOIN_COMMAND}" | sed 's/kubeadm join //')

  echo "Join arguments: ${JOIN_ARGS}"

  # Execute join script with join arguments
  echo "Joining Windows node ${display_name} to cluster..."
  ${windows_connect_command} "powershell -ExecutionPolicy Bypass -File c:\\k\\join-cluster.ps1 -JoinArgs '${JOIN_ARGS}' -WindowsEip '${windows_eip}'"

  echo "Windows worker node ${display_name} joined successfully!"
  echo
}

function copy_files_from_linux() {
  echo "Copying Kubernetes certificates and config from Linux node..."
  mkdir -p ./windows/kubeadm

  # Copy kubeconfig
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${LINUX_EIP}:/home/winfv/.kube/config ./windows/kubeadm/config

  # Copy Kubernetes PKI certificates (needed for authentication)
  ${MASTER_CONNECT_COMMAND} "sudo cp /etc/kubernetes/pki/ca.crt /tmp/ca.crt && sudo chmod 644 /tmp/ca.crt"
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${LINUX_EIP}:/tmp/ca.crt ./windows/kubeadm/

  echo "Kubernetes certificates copied successfully"
}

function prepare_windows_configuration() {
  echo "Preparing Windows configuration files..."

  # Extract client certificate and key data from the copied kubeconfig
  export CLIENT_CERT_DATA=$(grep 'client-certificate-data' ./windows/kubeadm/config | awk '{print $2}')
  export CLIENT_KEY_DATA=$(grep 'client-key-data' ./windows/kubeadm/config | awk '{print $2}')

  # Generate Windows-specific scripts with templates
  ${GOMPLATE} --file ./config-kubeadm --out ./windows/config

  echo "Windows configuration files prepared"
}

function prepare_windows_node() {
  local windows_eip="$1"
  local node_index="$2"  # Optional, for display purposes

  if [[ -z "$windows_eip" ]]; then
    echo "ERROR: No Windows node IP provided to prepare_windows_node"
    return 1
  fi

  local display_name="${node_index:-$windows_eip}"
  echo "====================================="
  echo "Preparing Windows node ${display_name} (${windows_eip})"
  echo "====================================="

  # Create SSH connect command
  local windows_connect_command="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 winfv@${windows_eip} powershell"

  # Create c:\k directory on Windows node if it doesn't exist
  echo "Creating c:\\k directory..."
  ${windows_connect_command} "if (-not (Test-Path c:\\k)) { New-Item -ItemType Directory -Path c:\\k -Force }"

  # Copy windows directory contents to c:\k\
  echo "Copying Windows files to node..."
  scp -r -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ./windows/* winfv@${windows_eip}:c:\\k\\

  # Enable containers feature (requires reboot)
  echo "Enabling Windows Containers feature..."
  ${windows_connect_command} c:\\k\\enable-containers-with-reboot.ps1

  # Wait for node to come back online after reboot
  sleep 10
  echo "Waiting for node to be ready after reboot..."
  retry_command 60 "${windows_connect_command} Write-Host 'Node is ready'"

  # Install containerd
  echo "Installing containerd..."
  if ! ${windows_connect_command} "c:\\k\\install-containerd.ps1 -ContainerDVersion ${CONTAINERD_VERSION}"; then
    echo "ERROR: Failed to install containerd on Windows node ${display_name}"
    echo "You can SSH to the node to debug: ${windows_connect_command}"
    return 1
  fi

  echo "Windows node ${display_name} prepared successfully"
  echo
  return 0
}

copy_scripts_to_linux_nodes
copy_scripts_to_windows_nodes

echo "Setting up Kubernetes cluster on Linux control plane..."
redirect_output setup_kubeadm_cluster
echo "✓ Kubernetes cluster initialized"

echo "Joining Linux worker nodes..."
redirect_output join_linux_worker_nodes
echo "✓ Linux worker nodes joined"

copy_files_from_linux
prepare_windows_configuration

# Prepare each Windows node individually
echo "Preparing ${WINDOWS_NODE_COUNT} Windows node(s)..."
for ((win_idx=0; win_idx<${WINDOWS_NODE_COUNT}; win_idx++)); do
  node_num=$((win_idx+1))
  echo "  Preparing Windows node ${node_num}..."
  redirect_output prepare_windows_node "${WINDOWS_EIPS[$win_idx]}" "${node_num}"
  echo "  ✓ Windows node ${node_num} prepared"
done
echo "✓ All Windows nodes prepared successfully"

# Join each Windows node to the cluster
echo "Joining ${WINDOWS_NODE_COUNT} Windows node(s) to the cluster..."
for ((win_idx=0; win_idx<${WINDOWS_NODE_COUNT}; win_idx++)); do
  node_num=$((win_idx+1))
  redirect_output join_windows_worker_node "${WINDOWS_EIPS[$win_idx]}" "${WINDOWS_PIPS[$win_idx]}" "${node_num}"
done
echo "All Windows nodes joined successfully!"
${MASTER_CONNECT_COMMAND} kubectl get nodes -o wide

echo
echo "Cluster setup complete! Final status:"
${MASTER_CONNECT_COMMAND} kubectl get pod -A -o wide
echo
