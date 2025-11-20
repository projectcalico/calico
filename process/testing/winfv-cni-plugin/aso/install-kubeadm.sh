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
  echo "Installing containerd..."
  sudo apt-get update
  sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
  
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  
  sudo apt-get update
  sudo apt-get install -y containerd.io
  
  # Configure containerd
  sudo mkdir -p /etc/containerd
  containerd config default | sudo tee /etc/containerd/config.toml
  sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
  sudo systemctl restart containerd
  sudo systemctl enable containerd
fi

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
  
  # Wait for API server to be ready
  echo "Waiting for API server to be ready..."
  ${MASTER_CONNECT_COMMAND} "kubectl wait --for=condition=Ready node --all --timeout=300s"
  
  # Remove control plane taints to allow scheduling pods on master (for single-node testing)
  echo "Removing control plane taints..."
  ${MASTER_CONNECT_COMMAND} "kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true"
  
  echo
  echo "Kubernetes cluster info:"
  ${MASTER_CONNECT_COMMAND} kubectl get nodes -o wide
  echo
  ${MASTER_CONNECT_COMMAND} kubectl version --short
  echo
  
  echo "Kubernetes cluster setup completed successfully!"
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
  
  # Extract client certificate and key data from the copied kubeconfig
  export CLIENT_CERT_DATA=$(grep 'client-certificate-data' ./windows/kubeadm/config | awk '{print $2}')
  export CLIENT_KEY_DATA=$(grep 'client-key-data' ./windows/kubeadm/config | awk '{print $2}')
  
  # Generate Windows-specific scripts with templates
  ${GOMPLATE} --file ./run-fv-cni-plugin.ps1 --out ./windows/run-fv.ps1
  ${GOMPLATE} --file ./config-kubeadm --out ./windows/config

  echo "Copying windows directory to Windows node..."
  # Copy local windows directory to Windows node.
  scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -r ./windows winfv@${WINDOWS_EIP}:c:\\k\\
  
  echo "Windows configuration files copied successfully"
}

function prepare_windows_node() {
  ${WINDOWS_CONNECT_COMMAND} c:\\k\\enable-containers-with-reboot.ps1
  sleep 10
  retry_command 60 "${WINDOWS_CONNECT_COMMAND} Get-HnsNetwork"

  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\install-containerd.ps1 -ContainerDVersion ${CONTAINERD_VERSION}"
  echo
}

setup_kubeadm_cluster
copy_files_from_linux
prepare_and_copy_windows_dir
prepare_windows_node
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
echo "All done."