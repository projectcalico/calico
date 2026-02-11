#!/bin/bash
set -e

echo "=== Joining Kubernetes cluster as worker node ==="

# Get the join command (should be passed as arguments)
JOIN_COMMAND="$*"

if [ -z "$JOIN_COMMAND" ]; then
  echo "ERROR: No join command provided"
  echo "Usage: $0 <kubeadm join command>"
  exit 1
fi

echo "Executing join command..."
sudo $JOIN_COMMAND

echo "Successfully joined the cluster as a worker node!"

