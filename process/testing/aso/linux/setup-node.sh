#!/bin/bash
set -eu -o pipefail

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

sudo sysctl --system || true # ignore errors from unrelated sysctl params in the base image

# Wait for containerd to be fully configured (the VM extension may still be running)
echo "Waiting for containerd to be installed and configured..."
for i in $(seq 1 31); do
  if command -v containerd &> /dev/null && [ -f /etc/containerd/config.toml ]; then
    if ! command -v systemctl &> /dev/null || systemctl is-active --quiet containerd; then
      break
    fi
  fi
  if [ "$i" -eq 31 ]; then
    echo "ERROR: containerd is not installed after 5 minutes"
    echo "Please ensure the VM extension in vmss-linux.yaml has installed containerd, created /etc/containerd/config.toml, and started the containerd service."
    exit 1
  fi
  sleep 10
done

echo "Containerd found: $(containerd --version)"

# Verify systemd cgroup is enabled
if ! grep -q "SystemdCgroup = true" /etc/containerd/config.toml; then
  echo "WARNING: SystemdCgroup is not enabled in containerd config"

  echo "Enabling SystemdCgroup in containerd config"
  # Enable systemd cgroup driver (required for Kubernetes)
  sudo sed -i "s/SystemdCgroup = false/SystemdCgroup = true/g" /etc/containerd/config.toml
  sudo systemctl restart containerd
fi

# Ensure containerd is running
sudo systemctl status containerd --no-pager || {
  echo "ERROR: containerd service is not running!"
  exit 1
}

# Install kubeadm, kubelet, and kubectl
KUBE_VERSION=${1:-"v1.33.7"}
# Extract major.minor version (e.g., v1.33.6 -> v1.33)
KUBE_MAJOR_MINOR=$(echo "${KUBE_VERSION}" | cut -d'.' -f1,2)
echo "Installing kubeadm, kubelet, and kubectl ${KUBE_VERSION}..."
echo "Using repository version: ${KUBE_MAJOR_MINOR}"
sudo apt-get -o DPkg::Lock::Timeout=60 update
sudo apt-get -o DPkg::Lock::Timeout=60 install -y apt-transport-https ca-certificates curl gpg

# Create keyrings directory
sudo mkdir -p /etc/apt/keyrings

# Add Kubernetes apt repository
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${KUBE_MAJOR_MINOR}/deb/Release.key" | sudo gpg --batch --yes --no-tty --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBE_MAJOR_MINOR}/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Install Kubernetes components
sudo apt-get -o DPkg::Lock::Timeout=60 update
sudo apt-get -o DPkg::Lock::Timeout=60 install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Enable kubelet
sudo systemctl enable kubelet

echo "Kubeadm installation completed successfully!"

