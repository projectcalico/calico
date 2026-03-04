## Windows FV Infrastructure

This directory contains scripts and manifests to set up a Windows kubeadm infrastructure on Azure using Azure Service Operator. It creates three Linux nodes and two Windows nodes by default.

### Prerequisites

- Azure CLI must be installed
- Required Azure environment variables must be set (see Step 1)

### Steps

1. Set the required environment variables in `export-env.sh`.

2. Run `make setup-kubeadm` to create the kubeadm cluster.

3. Run `make install-calico` to install Calico on the cluster.

4. Export `KUBECONFIG=./kubeconfig` to access the cluster.

### Access Linux or Windows Nodes

Helper scripts will be generated to SSH or SCP into each node. See the individual scripts for details.

For example:
```bash
# Usage: ./ssh-node-windows.sh [node_index] [command]
# Examples:
#   ./ssh-node-windows.sh 0 "Get-Process"     # SSH to first Windows node (index 0)
#   ./ssh-node-windows.sh 1 "ipconfig /all"   # SSH to second Windows node (index 1)
#   ./ssh-node-windows.sh "Get-Process"       # SSH to first node (default, backward compatible)
```

### Cleanup

Run `make dist-clean`.
