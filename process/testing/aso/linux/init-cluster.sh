#!/bin/bash
set -e

echo "=== Initializing Kubernetes cluster with kubeadm ==="

# Get the advertise address (should be passed as argument)
ADVERTISE_ADDRESS=${1}
POD_NETWORK_CIDR=${2:-"192.168.0.0/16"}
SERVICE_CIDR=${3:-"10.96.0.0/12"}
EXTERNAL_IP=${4}  # Optional external IP for certificate SANs

if [ -z "$ADVERTISE_ADDRESS" ]; then
  echo "ERROR: No advertise address provided"
  echo "Usage: $0 <advertise-address> [pod-network-cidr] [service-cidr] [external-ip]"
  exit 1
fi

echo "Initializing cluster with:"
echo "  API Server Address: ${ADVERTISE_ADDRESS}"
echo "  Pod Network CIDR: ${POD_NETWORK_CIDR}"
echo "  Service CIDR: ${SERVICE_CIDR}"
echo "  External IP: ${EXTERNAL_IP:-none}"

# Build the cert-extra-sans parameter
CERT_SANS="${ADVERTISE_ADDRESS}"
if [ -n "$EXTERNAL_IP" ]; then
  CERT_SANS="${CERT_SANS},${EXTERNAL_IP}"
  echo "  Certificate will include both internal and external IPs"
fi

# Initialize kubeadm cluster
sudo kubeadm init \
  --apiserver-advertise-address=${ADVERTISE_ADDRESS} \
  --apiserver-cert-extra-sans=${CERT_SANS} \
  --pod-network-cidr=${POD_NETWORK_CIDR} \
  --service-cidr=${SERVICE_CIDR}

# Set up kubeconfig for current user
echo "Setting up kubeconfig..."
mkdir -p $HOME/.kube
sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

echo "Kubernetes cluster initialized successfully!"
echo "You can now use kubectl to interact with the cluster."

