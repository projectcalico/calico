#!/bin/bash
set -e

echo "=== Initializing Kubernetes cluster with kubeadm ==="

KUBEADM_CONFIG=${1}

if [ -z "${KUBEADM_CONFIG}" ]; then
  echo "ERROR: No kubeadm config yaml provided"
  exit 1
fi

if [ ! -f "${KUBEADM_CONFIG}" ]; then
  echo "ERROR: kubeadm config yaml file ${KUBEADM_CONFIG} not found"
  echo "Usage: $0 <kubeadm-config-yaml>"
  exit 1
fi

echo "Initializing cluster with:"
echo "  kubeadm config yaml: ${KUBEADM_CONFIG}"

# Initialize kubeadm cluster
sudo kubeadm init --config "${KUBEADM_CONFIG}"

# Set up kubeconfig for current user
echo "Setting up kubeconfig..."
mkdir -p $HOME/.kube
sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

echo "Kubernetes cluster initialized successfully!"
echo "You can now use kubectl to interact with the cluster."
