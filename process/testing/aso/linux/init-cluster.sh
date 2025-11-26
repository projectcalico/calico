#!/bin/bash
set -e

echo "=== Initializing Kubernetes cluster with kubeadm ==="

# Get the advertise address (should be passed as argument)
ADVERTISE_ADDRESS=${1}
POD_NETWORK_CIDR=${2:-"10.244.0.0/16"}
SERVICE_CIDR=${3:-"10.96.0.0/12"}

if [ -z "$ADVERTISE_ADDRESS" ]; then
  echo "ERROR: No advertise address provided"
  echo "Usage: $0 <advertise-address> [pod-network-cidr] [service-cidr]"
  exit 1
fi

echo "Initializing cluster with:"
echo "  API Server Address: ${ADVERTISE_ADDRESS}"
echo "  Pod Network CIDR: ${POD_NETWORK_CIDR}"
echo "  Service CIDR: ${SERVICE_CIDR}"

# Initialize kubeadm cluster
sudo kubeadm init \
  --apiserver-advertise-address=${ADVERTISE_ADDRESS} \
  --apiserver-cert-extra-sans=${ADVERTISE_ADDRESS} \
  --pod-network-cidr=${POD_NETWORK_CIDR} \
  --service-cidr=${SERVICE_CIDR} \
  --skip-phases=addon/kube-proxy

# Set up kubeconfig for current user
echo "Setting up kubeconfig..."
mkdir -p $HOME/.kube
sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

echo "Kubernetes cluster initialized successfully!"
echo "You can now use kubectl to interact with the cluster."

