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

. ../../util/utils.sh

. ./vmss.sh info

: ${KUBECTL:=./bin/kubectl}
: ${GOMPLATE:=./bin/gomplate}
: ${BACKEND:?Error: BACKEND is not set}

# Reconstruct arrays from exported string variables
# Bash arrays cannot be exported across shells, so we export them as space-separated strings
if [[ -n "${LINUX_EIPS_STR}" ]]; then
  read -ra LINUX_EIPS <<< "${LINUX_EIPS_STR}"
fi

if [[ -n "${LINUX_PIPS_STR}" ]]; then
  read -ra LINUX_PIPS <<< "${LINUX_PIPS_STR}"
fi

if [[ -n "${WINDOWS_EIPS_STR}" ]]; then
  read -ra WINDOWS_EIPS <<< "${WINDOWS_EIPS_STR}"
fi

if [[ -n "${WINDOWS_PIPS_STR}" ]]; then
  read -ra WINDOWS_PIPS <<< "${WINDOWS_PIPS_STR}"
fi

if [[ ${#LINUX_PIPS[@]} -eq 0 && -n "${LINUX_PIP}" ]]; then
  LINUX_PIPS=("${LINUX_PIP}")
fi

if [[ ${#WINDOWS_PIPS[@]} -eq 0 && -n "${WINDOWS_PIP}" ]]; then
  WINDOWS_PIPS=("${WINDOWS_PIP}")
fi

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

function check_vm_extension_logs() {
  local vm_ip="$1"
  local vm_name="$2"
  
  echo ""
  echo "=========================================="
  echo "Fetching VM extension logs from ${vm_name} (${vm_ip})"
  echo "=========================================="
  
  local ssh_command="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 winfv@${vm_ip}"
  
  echo ""
  echo "--- Custom Script Extension Handler Log ---"
  ${ssh_command} "sudo cat /var/log/azure/custom-script/handler.log 2>/dev/null || echo 'Handler log not found'"
  
  echo ""
  echo "--- Extension stdout (last 50 lines) ---"
  ${ssh_command} "sudo tail -50 /var/lib/waagent/custom-script/download/0/stdout 2>/dev/null || echo 'stdout not found'"
  
  echo ""
  echo "--- Extension stderr (last 50 lines) ---"
  ${ssh_command} "sudo tail -50 /var/lib/waagent/custom-script/download/0/stderr 2>/dev/null || echo 'stderr not found'"
  
  echo ""
  echo "--- Extension files ---"
  ${ssh_command} "sudo ls -la /var/lib/waagent/custom-script/download/0/ 2>/dev/null || echo 'Extension directory not found'"
  
  echo ""
  echo "--- Walinuxagent service log (last 50 lines) ---"
  ${ssh_command} "sudo journalctl -u walinuxagent.service -n 50 --no-pager 2>/dev/null || echo 'walinuxagent logs not found'"
  
  echo ""
  echo "--- Checking kubeadm installation ---"
  ${ssh_command} "which kubeadm 2>/dev/null || echo 'kubeadm not found in PATH'"
  ${ssh_command} "which kubelet 2>/dev/null || echo 'kubelet not found in PATH'"
  ${ssh_command} "which kubectl 2>/dev/null || echo 'kubectl not found in PATH'"
  
  echo ""
  echo "=========================================="
  echo "End of extension logs for ${vm_name}"
  echo "=========================================="
}

function setup_kubeadm_cluster() {
  echo "Setting up Kubernetes cluster with kubeadm..."
  
  # Wait for VM extensions to complete (kubeadm installation)
  echo "Waiting for VM extensions to complete on control plane node..."
  local max_wait=600  # 10 minutes
  local elapsed=0
  local check_interval=10
  
  while [ $elapsed -lt $max_wait ]; do
    if ${MASTER_CONNECT_COMMAND} "command -v kubeadm &>/dev/null"; then
      echo "VM extensions completed successfully - kubeadm is installed"
      break
    fi
    echo "Waiting for VM extensions to install kubeadm... (${elapsed}s/${max_wait}s)"
    sleep $check_interval
    elapsed=$((elapsed + check_interval))
  done
  
  if [ $elapsed -ge $max_wait ]; then
    echo "ERROR: VM extensions did not complete within ${max_wait} seconds"
    echo ""
    check_vm_extension_logs "${LINUX_EIP}" "vm-linux-1"
    return 1
  fi
  
  # Verify prerequisites are installed (by VM extension)
  echo "Verifying all prerequisites are installed..."
  if ! ${MASTER_CONNECT_COMMAND} bash -s <<'EOF'
set -e

# Verify containerd is installed and running
if ! command -v containerd &> /dev/null; then
  echo "ERROR: containerd is not installed!"
  exit 1
fi

echo "Containerd found: $(containerd --version)"

# Verify containerd is running
sudo systemctl status containerd --no-pager || {
  echo "ERROR: containerd service is not running!"
  exit 1
}

# Verify kubeadm is installed
if ! command -v kubeadm &> /dev/null; then
  echo "ERROR: kubeadm is not installed!"
  exit 1
fi

echo "Kubeadm found: $(kubeadm version -o short)"
echo "Kubelet found: $(kubelet --version)"
echo "Kubectl found: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"

# Verify swap is disabled
if [ $(swapon --show | wc -l) -gt 0 ]; then
  echo "ERROR: Swap is still enabled!"
  exit 1
fi

echo "All prerequisites verified successfully"
EOF
  then
    echo ""
    echo "ERROR: Prerequisite verification failed!"
    check_vm_extension_logs "${LINUX_EIP}" "vm-linux-1"
    return 1
  fi

  # Initialize kubeadm cluster
  echo "Initializing Kubernetes cluster with kubeadm..."
  LOCAL_IP_ENV=${LINUX_PIP}
  
  ${MASTER_CONNECT_COMMAND} "sudo kubeadm init \
    --apiserver-advertise-address=${LOCAL_IP_ENV} \
    --apiserver-cert-extra-sans=${LOCAL_IP_ENV} \
    --pod-network-cidr=10.244.0.0/16 \
    --service-cidr=10.96.0.0/12 \
    --skip-phases=addon/kube-proxy"
  
  # Set up kubeconfig for winfv user
  ${MASTER_CONNECT_COMMAND} bash -s <<'EOF'
mkdir -p $HOME/.kube
sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
EOF
  
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
    
    # Verify prerequisites are installed (by VM extension)
    echo "Verifying kubeadm installation on Linux worker node ${node_num}..."
    ${linux_connect_command} bash -s <<'WORKER_EOF'
set -e

# Verify kubeadm is installed
if ! command -v kubeadm &> /dev/null; then
  echo "ERROR: kubeadm is not installed!"
  echo "Please ensure the VM extension in vmss-linux.yaml has installed kubeadm."
  exit 1
fi

echo "Kubeadm found: $(kubeadm version -o short)"
echo "Kubelet found: $(kubelet --version)"
echo "Prerequisites verified successfully"
WORKER_EOF
    
    # Join the node to the cluster
    echo "Joining Linux worker node ${node_num} to the cluster..."
    echo "Using join command: ${KUBEADM_JOIN_COMMAND}"
    
    if ! ${linux_connect_command} "sudo ${KUBEADM_JOIN_COMMAND}"; then
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
  
  # Create a PowerShell script for installing kubeadm on Windows using PrepareNode.ps1
  cat > /tmp/install-kubeadm-windows-${display_name}.ps1 <<'PSEOF'
# Use PrepareNode.ps1 from sig-windows-tools to set up Kubernetes binaries
$K8S_VERSION = "v1.33.0"
$KUBE_BIN_DIR = "C:\k"

# Ensure C:\k directory exists
if (!(Test-Path $KUBE_BIN_DIR)) {
    New-Item -ItemType Directory -Path $KUBE_BIN_DIR -Force
}

Write-Host "Downloading PrepareNode.ps1 from sig-windows-tools..."
curl.exe -L -o PrepareNode.ps1 https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/hostprocess/PrepareNode.ps1

if (!(Test-Path ".\PrepareNode.ps1")) {
    Write-Error "Failed to download PrepareNode.ps1"
    exit 1
}

Write-Host "Running PrepareNode.ps1 to install Kubernetes binaries (version: $K8S_VERSION)..."
.\PrepareNode.ps1 -KubernetesVersion $K8S_VERSION

if ($LASTEXITCODE -ne 0) {
    Write-Error "PrepareNode.ps1 failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Kubernetes binaries installed successfully"
Write-Host "Verifying installations..."
if (Test-Path "$KUBE_BIN_DIR\kubeadm.exe") {
    Write-Host "Kubeadm version: $(& $KUBE_BIN_DIR\kubeadm.exe version)"
} else {
    Write-Error "kubeadm.exe not found at $KUBE_BIN_DIR\kubeadm.exe"
    exit 1
}

if (Test-Path "$KUBE_BIN_DIR\kubelet.exe") {
    Write-Host "Kubelet version: $(& $KUBE_BIN_DIR\kubelet.exe --version)"
} else {
    Write-Error "kubelet.exe not found at $KUBE_BIN_DIR\kubelet.exe"
    exit 1
}

if (Test-Path "$KUBE_BIN_DIR\kubectl.exe") {
    Write-Host "Kubectl version: $(& $KUBE_BIN_DIR\kubectl.exe version)"
} else {
    Write-Warning "kubectl.exe not found at $KUBE_BIN_DIR\kubectl.exe"
}
PSEOF

  # Copy script to Windows node
  echo "Installing kubeadm on Windows node ${display_name}..."
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /tmp/install-kubeadm-windows-${display_name}.ps1 winfv@${windows_eip}:c:\\k\\
  
  # Execute the script on Windows
  ${windows_connect_command} "powershell -ExecutionPolicy Bypass -File c:\\k\\install-kubeadm-windows-${display_name}.ps1"
  
  # Create join script with the actual join command
  # Extract just the token and discovery hash from the join command
  JOIN_ARGS=$(echo "${KUBEADM_JOIN_COMMAND}" | sed 's/kubeadm join //')
  
  cat > /tmp/join-cluster-windows-${display_name}.ps1 <<PSEOF
# Join Windows node to Kubernetes cluster
\$KUBE_BIN_DIR = "C:\k"

# Ensure PATH includes C:\k
\$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine")

Write-Host "Joining cluster at ${LINUX_PIP}:6443..."
Write-Host "Using kubeadm at: \$KUBE_BIN_DIR\kubeadm.exe"
Write-Host "Kubelet location: \$KUBE_BIN_DIR\kubelet.exe"

# Verify kubelet exists
if (!(Test-Path "\$KUBE_BIN_DIR\kubelet.exe")) {
    Write-Error "kubelet.exe not found at \$KUBE_BIN_DIR\kubelet.exe"
    Start-Sleep -Seconds 600
    exit 1
}

# Print the actual join command
Write-Host ""
Write-Host "=========================================="
Write-Host "Executing kubeadm join command:"
Write-Host "\$KUBE_BIN_DIR\kubeadm.exe join ${JOIN_ARGS} --cri-socket npipe:////./pipe/containerd-containerd"
Write-Host "=========================================="
Write-Host ""

# Run kubeadm join with full path
\$joinResult = & \$KUBE_BIN_DIR\kubeadm.exe join ${JOIN_ARGS} --cri-socket npipe:////./pipe/containerd-containerd

# Check if join failed
if (\$LASTEXITCODE -ne 0) {
    Write-Error "Kubeadm join failed with exit code \$LASTEXITCODE"
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "Join failed! Sleeping for 10 minutes for debugging..."
    Write-Host "You can SSH to this node at: ${windows_eip}"
    Write-Host "=========================================="
    Start-Sleep -Seconds 600
    exit \$LASTEXITCODE
}

Write-Host "Successfully joined the cluster!"
PSEOF

  # Copy and execute join script
  echo "Joining Windows node ${display_name} to cluster..."
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /tmp/join-cluster-windows-${display_name}.ps1 winfv@${windows_eip}:c:\\k\\
  ${windows_connect_command} "powershell -ExecutionPolicy Bypass -File c:\\k\\join-cluster-windows-${display_name}.ps1"
  
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
  ${GOMPLATE} --file ./run-fv-cni-plugin.ps1 --out ./windows/run-fv.ps1
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
  echo "DEBUG: prepare_windows_node function completing for node ${display_name}"
  echo
  return 0
}

setup_kubeadm_cluster
join_linux_worker_nodes
copy_files_from_linux
prepare_windows_configuration

# Prepare each Windows node individually
echo "Preparing ${WINDOWS_NODE_COUNT} Windows node(s)..."
echo "DEBUG: WINDOWS_NODE_COUNT=${WINDOWS_NODE_COUNT}"
echo "DEBUG: WINDOWS_EIPS array: ${WINDOWS_EIPS[@]}"
for ((win_idx=0; win_idx<${WINDOWS_NODE_COUNT}; win_idx++)); do
  echo "DEBUG: Top of loop - win_idx=${win_idx}"
  node_num=$((win_idx+1))
  echo "DEBUG: Calling prepare_windows_node for win_idx=${win_idx}, node_num=${node_num}, EIP=${WINDOWS_EIPS[$win_idx]}"
  prepare_windows_node "${WINDOWS_EIPS[$win_idx]}" "${node_num}"
  echo "DEBUG: Returned from prepare_windows_node for win_idx=${win_idx}, node_num=${node_num}"
  echo "DEBUG: About to loop increment - current win_idx=${win_idx}"
done
echo "DEBUG: Loop finished - final win_idx=${win_idx}"
echo "All Windows nodes prepared successfully"

# Join each Windows node to the cluster
echo "Joining ${WINDOWS_NODE_COUNT} Windows node(s) to the cluster..."
for ((win_idx=0; win_idx<${WINDOWS_NODE_COUNT}; win_idx++)); do
  node_num=$((win_idx+1))
  join_windows_worker_node "${WINDOWS_EIPS[$win_idx]}" "${WINDOWS_PIPS[$win_idx]}" "${node_num}"
done
echo "All Windows nodes joined successfully!"
${MASTER_CONNECT_COMMAND} kubectl get nodes -o wide

echo
echo "Cluster setup complete! Final node status:"
${MASTER_CONNECT_COMMAND} kubectl get nodes -o wide
echo

exit 0

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