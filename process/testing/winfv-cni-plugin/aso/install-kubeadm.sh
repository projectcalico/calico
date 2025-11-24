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

# Rebuild arrays from the single variables if arrays are empty
# This is a workaround for bash array export issues across sourcing
if [[ ${#LINUX_EIPS[@]} -eq 0 && -n "${LINUX_EIP}" ]]; then
  echo "WARNING: LINUX_EIPS array is empty, rebuilding from LINUX_EIP"
  LINUX_EIPS=("${LINUX_EIP}")
  # For multiple nodes, we would need to query ASO directly
  # For now, assume single node setup
fi

if [[ ${#WINDOWS_EIPS[@]} -eq 0 && -n "${WINDOWS_EIP}" ]]; then
  echo "WARNING: WINDOWS_EIPS array is empty, rebuilding from WINDOWS_EIP"
  WINDOWS_EIPS=("${WINDOWS_EIP}")
  # For multiple nodes, we would need to query ASO directly
  # For now, assume single node setup
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
echo "  LINUX_EIPS: ${LINUX_EIPS[@]}"
echo "  LINUX_EIP (first): ${LINUX_EIP}"
echo "  WINDOWS_EIPS: ${WINDOWS_EIPS[@]}"
echo "  WINDOWS_EIP (first): ${WINDOWS_EIP}"
echo "========================================"
echo

function setup_kubeadm_cluster() {
  echo "Installing kubeadm and Kubernetes 1.33 on Linux VM..."
  
  # Install prerequisites and kubeadm
  ${MASTER_CONNECT_COMMAND} bash -s <<'EOF'
set -e

# Disable swap (required for Kubernetes)
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Load required kernel modules
cat <<MODULES | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
MODULES

sudo modprobe overlay
sudo modprobe br_netfilter

# Set sysctl params required by Kubernetes
cat <<SYSCTL | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
SYSCTL

sudo sysctl --system

# Install containerd if not already installed
if ! command -v containerd &> /dev/null; then
  echo "ERROR: containerd is not installed!"
  echo "Please ensure the VM extension in vmss-linux.yaml has installed containerd."
  exit 1
fi

echo "Containerd found: $(containerd --version)"

# Verify containerd configuration
if [ ! -f /etc/containerd/config.toml ]; then
  echo "ERROR: containerd config file /etc/containerd/config.toml not found!"
  exit 1
fi

# Verify systemd cgroup is enabled
if ! grep -q "SystemdCgroup = true" /etc/containerd/config.toml; then
  echo "WARNING: SystemdCgroup is not enabled in containerd config"
  echo "This may cause issues with Kubernetes. Please check vmss-linux.yaml extension."
fi

# Ensure containerd is running
sudo systemctl status containerd --no-pager || {
  echo "ERROR: containerd service is not running!"
  exit 1
}

# Install kubeadm, kubelet, and kubectl for Kubernetes 1.33
echo "Installing kubeadm, kubelet, and kubectl v1.33..."
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.33/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.33/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Enable kubelet
sudo systemctl enable kubelet

echo "Kubeadm installation completed"
EOF

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
    
    # Ensure prerequisites are installed on the worker node
    echo "Installing kubeadm, kubelet, and kubectl on Linux worker node ${node_num}..."
    ${linux_connect_command} bash -s <<'WORKER_EOF'
set -e

# Install prerequisites
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

# Add Kubernetes apt repository
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.33/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.33/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Install kubeadm, kubelet, and kubectl
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Enable kubelet
sudo systemctl enable --now kubelet

echo "Kubernetes components installed successfully"
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
  echo "Joining Windows worker node(s) to the cluster..."
  
  # Validate that we have Windows node IPs
  if [[ ${#WINDOWS_EIPS[@]} -eq 0 ]]; then
    echo "ERROR: WINDOWS_EIPS array is empty. Cannot join Windows nodes."
    echo "Debug info:"
    echo "  WINDOWS_NODE_COUNT: ${WINDOWS_NODE_COUNT}"
    echo "  WINDOWS_EIP (single): ${WINDOWS_EIP}"
    echo "  WINDOWS_EIPS array: ${WINDOWS_EIPS[@]}"
    return 1
  fi
  
  # Loop through all Windows nodes
  for ((i=0; i<${WINDOWS_NODE_COUNT}; i++)); do
    local node_num=$((i+1))
    local windows_eip="${WINDOWS_EIPS[$i]}"
    local windows_pip="${WINDOWS_PIPS[$i]}"
    
    if [[ -z "$windows_eip" ]]; then
      echo "ERROR: Windows node ${node_num} EIP is empty!"
      return 1
    fi
    
    local windows_connect_command="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 winfv@${windows_eip} powershell"
    
    echo "====================================="
    echo "Joining Windows Node ${node_num} (${windows_eip})"
    echo "====================================="
    
    # Create a PowerShell script for installing kubeadm on Windows using PrepareNode.ps1
    cat > /tmp/install-kubeadm-windows-${node_num}.ps1 <<'PSEOF'
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

    # Copy script to Windows node using helper script
    echo "Installing kubeadm on Windows node ${node_num}..."
    ./scp-to-windows.sh $i /tmp/install-kubeadm-windows-${node_num}.ps1 c:\\k\\
    
    # Execute the script on Windows using helper script
    ./ssh-node-windows.sh $i "powershell -ExecutionPolicy Bypass -File c:\\k\\install-kubeadm-windows-${node_num}.ps1"
    
    # Create join script with the actual join command
    # Extract just the token and discovery hash from the join command
    JOIN_ARGS=$(echo "${KUBEADM_JOIN_COMMAND}" | sed 's/kubeadm join //')
    
    cat > /tmp/join-cluster-windows-${node_num}.ps1 <<PSEOF
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

    # Copy and execute join script using helper scripts
    echo "Joining Windows node ${node_num} to cluster..."
    ./scp-to-windows.sh $i /tmp/join-cluster-windows-${node_num}.ps1 c:\\k\\
    ./ssh-node-windows.sh $i "powershell -ExecutionPolicy Bypass -File c:\\k\\join-cluster-windows-${node_num}.ps1"
    
    echo "Windows worker node ${node_num} joined successfully!"
    echo
  done
  
  echo "All Windows worker nodes joined successfully!"
  ${MASTER_CONNECT_COMMAND} kubectl get nodes -o wide
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

function prepare_and_copy_windows_dir () {
  echo "Preparing Windows configuration files..."
  
  # Validate that we have Windows node IPs
  if [[ ${#WINDOWS_EIPS[@]} -eq 0 ]]; then
    echo "ERROR: WINDOWS_EIPS array is empty. Windows VMs may not have been created or IPs not retrieved."
    echo "WINDOWS_NODE_COUNT: ${WINDOWS_NODE_COUNT}"
    echo "Available variables:"
    echo "  LINUX_EIPS: ${LINUX_EIPS[@]}"
    echo "  WINDOWS_EIPS: ${WINDOWS_EIPS[@]}"
    echo "  WINDOWS_EIP (single): ${WINDOWS_EIP}"
    return 1
  fi
  
  # Extract client certificate and key data from the copied kubeconfig
  export CLIENT_CERT_DATA=$(grep 'client-certificate-data' ./windows/kubeadm/config | awk '{print $2}')
  export CLIENT_KEY_DATA=$(grep 'client-key-data' ./windows/kubeadm/config | awk '{print $2}')
  
  # Generate Windows-specific scripts with templates
  ${GOMPLATE} --file ./run-fv-cni-plugin.ps1 --out ./windows/run-fv.ps1
  ${GOMPLATE} --file ./config-kubeadm --out ./windows/config

  echo "Copying windows directory to all Windows nodes..."
  # Copy local windows directory to all Windows nodes
  # Note: Using scp directly with -r flag for recursive directory copy
  for ((i=0; i<${WINDOWS_NODE_COUNT}; i++)); do
    local node_num=$((i+1))
    local windows_eip="${WINDOWS_EIPS[$i]}"
    
    if [[ -z "$windows_eip" ]]; then
      echo "ERROR: Windows node ${node_num} EIP is empty!"
      return 1
    fi
    
    echo "Copying to Windows node ${node_num} (${windows_eip})..."
    # Use scp directly with -r for directory
    scp -r -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ./windows winfv@${windows_eip}:c:\\k\\
  done
  
  echo "Windows configuration files copied successfully to all nodes"
}

function prepare_windows_node() {
  echo "Preparing all Windows nodes..."
  
  # Validate that we have Windows node IPs
  if [[ ${#WINDOWS_EIPS[@]} -eq 0 ]]; then
    echo "ERROR: WINDOWS_EIPS array is empty. Cannot prepare Windows nodes."
    return 1
  fi
  
  for ((i=0; i<${WINDOWS_NODE_COUNT}; i++)); do
    local node_num=$((i+1))
    local windows_eip="${WINDOWS_EIPS[$i]}"
    
    if [[ -z "$windows_eip" ]]; then
      echo "ERROR: Windows node ${node_num} EIP is empty!"
      return 1
    fi
    
    echo "Preparing Windows node ${node_num} (${windows_eip})..."
    # Get the connect command for this node
    local connect_var="WINDOWS_NODE_${i}_CONNECT_PS"
    local windows_connect_command="${!connect_var}"

    ${windows_connect_command} c:\\k\\enable-containers-with-reboot.ps1

  sleep 10
    retry_command 60 "${windows_connect_command} Write-Host 'Node is ready'"

    echo "Installing containerd on Windows node ${node_num}..."
    if ! ${windows_connect_command} "c:\\k\\install-containerd.ps1 -ContainerDVersion ${CONTAINERD_VERSION}"; then
      echo "ERROR: Failed to install containerd on Windows node ${node_num}"
      echo "You can SSH to the node to debug: ${windows_connect_command}"
      return 1
    fi
    echo

    echo "Windows node ${node_num} prepared successfully"
  echo
  done
  
  echo "All Windows nodes prepared successfully"
}

setup_kubeadm_cluster
join_linux_worker_nodes
copy_files_from_linux
prepare_and_copy_windows_dir
prepare_windows_node
join_windows_worker_node

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