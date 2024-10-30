## Windows FV infrastructure
This directory contains scripts and manifests to setup Windows FV infrastructure.

### Steps
1. Export Environment variables. See example below (or `export-env.sh`):
```
export CLUSTER_NAME_CAPZ="my-win-capz-cluster"
export AZURE_LOCATION="westcentralus"

export AZURE_CONTROL_PLANE_MACHINE_TYPE="Standard_D2s_v3"
export AZURE_NODE_MACHINE_TYPE="Standard_D2s_v3"

export KUBE_VERSION="v1.30.4"
export CLUSTER_API_VERSION="v1.5.1"
export AZURE_PROVIDER_VERSION="v1.10.4"
export KIND_VERSION="v0.24.0"

# run "az ad sp list --spn your-client-id" to get information.
export AZURE_SUBSCRIPTION_ID="<your subscription id>"

# Create an Azure Service Principal and paste the output here
export AZURE_TENANT_ID="<your tenant id>"
export AZURE_CLIENT_ID="<your client id>"
export AZURE_CLIENT_SECRET="<your client secrect>"
```

When running Calico Enterprise, larger VMs are necessary, so use for example:
```
export AZURE_NODE_MACHINE_TYPE="Standard_D4s_v3"
```

2. Create an azure cluster with 2 Linux nodes and 2 Windows nodes.
```
make create-cluster
```

3. Install Calico
```
make install-calico
```

Optionally, define `PRODUCT`, `RELEASE_STREAM` and/or `HASH_RELEASE`:
```
make install-calico PRODUCT=calient RELEASE_STREAM=master HASH_RELEASE=true
```

(Use `RELEASE_STREAM=local` to use local manifests from the monorepo instead of pulling them)

To access your cluster, run `kubectl --kubeconfig=./kubeconfig ...`

### Access Linux or Windows nodes
```
make generate-helpers
```
Helper scripts which can be used to ssh or scp into each node are generated. See the individual scripts for details.

### Cleanup
```
make delete-cluster
make clean
```
