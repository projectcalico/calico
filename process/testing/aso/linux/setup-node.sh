#!/bin/bash
set -e

echo "=== Setting up Kubernetes prerequisites ==="

# Disable swap (required for Kubernetes)
echo "Disabling swap..."
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Load required kernel modules
echo "Loading kernel modules..."
cat <<MODULES | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
MODULES

sudo modprobe overlay
sudo modprobe br_netfilter

# Set sysctl params required by Kubernetes
echo "Setting sysctl params..."
cat <<SYSCTL | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
SYSCTL

sudo sysctl --system

# Verify containerd is installed
echo "Verifying containerd..."
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

# Install kubeadm, kubelet, and kubectl
KUBE_VERSION=${1:-"v1.33.6"}
# Extract major.minor version (e.g., v1.33.6 -> v1.33)
KUBE_MAJOR_MINOR=$(echo "${KUBE_VERSION}" | cut -d'.' -f1,2)
echo "Installing kubeadm, kubelet, and kubectl ${KUBE_VERSION}..."
echo "Using repository version: ${KUBE_MAJOR_MINOR}"
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

# Create keyrings directory
sudo mkdir -p /etc/apt/keyrings

# Add Kubernetes apt repository
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${KUBE_MAJOR_MINOR}/deb/Release.key" | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBE_MAJOR_MINOR}/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Enable kubelet
sudo systemctl enable kubelet

echo "Kubeadm installation completed successfully!"

