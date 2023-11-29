export CLUSTER_NAME_CAPZ="${CLUSTER_NAME_CAPZ:=${USER}-capz-win}"
export AZURE_LOCATION="${AZURE_LOCATION:="westcentralus"}"

# [Optional] Select resource group. The default value is ${CLUSTER_NAME_CAPZ}-rg.
export AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:=${CLUSTER_NAME_CAPZ}-rg}"

# Optional, can be windows-2019 or windows-2022 (default)
# https://capz.sigs.k8s.io/developers/development.html
# https://github.com/kubernetes-sigs/cluster-api-provider-azure/blob/main/templates/flavors/machinepool-windows/machine-pool-deployment-windows.yaml#L29
export WINDOWS_SERVER_VERSION="${WINDOWS_SERVER_VERSION:="windows-2022"}"

# Select VM types ("Standard_D2s_v3" is recommented for OSS Calico)
export AZURE_CONTROL_PLANE_MACHINE_TYPE="${AZURE_CONTROL_PLANE_MACHINE_TYPE:="Standard_D2s_v3"}"
export AZURE_NODE_MACHINE_TYPE="${AZURE_NODE_MACHINE_TYPE:="Standard_D2s_v3"}"

# Get KINDEST_NODE_VERSION variable from metadata.mk, default to a value if it cannot be found
SCRIPT_CURRENT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
METADATAMK=${SCRIPT_CURRENT_DIR}/../../../metadata.mk
if [ -f ${METADATAMK} ]; then
    export KUBE_VERSION=$(grep KINDEST_NODE_VERSION= ${METADATAMK} | cut -d "=" -f 2)
else
    export KUBE_VERSION=v1.27.11
fi
export CLUSTER_API_VERSION="${CLUSTER_API_VERSION:="v1.6.3"}"
export AZURE_PROVIDER_VERSION="${AZURE_PROVIDER_VERSION:="v1.13.2"}"
export KIND_VERSION="${KIND_VERSION:="v0.22.0"}"
export CONTAINERD_VERSION="${CONTAINERD_VERSION:="v1.7.13"}"
export CALICO_VERSION="${CALICO_VERSION:="v3.28.1"}"
