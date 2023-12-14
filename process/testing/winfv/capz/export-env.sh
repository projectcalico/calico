export CLUSTER_NAME_CAPZ="${CLUSTER_NAME_CAPZ:=${USER}-capz-win}"
export AZURE_LOCATION="${AZURE_LOCATION:="westcentralus"}"

# [Optional] Select resource group. The default value is ${CLUSTER_NAME_CAPZ}-rg.
export AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:=${CLUSTER_NAME_CAPZ}-rg}"

# Optional, can be windows-2019 or windows-2022 (default)
# https://capz.sigs.k8s.io/developers/development.html
# https://github.com/kubernetes-sigs/cluster-api-provider-azure/blob/main/templates/flavors/machinepool-windows/machine-pool-deployment-windows.yaml#L29
export WINDOWS_SERVER_VERSION="${WINDOWS_SERVER_VERSION:="windows-2022"}"

# Select VM types ("Standard_D2s_v3" is recommented for OSS Calico and "Standard_D4s_v3" is recommended for Calico Enterprise)
export AZURE_CONTROL_PLANE_MACHINE_TYPE="${AZURE_CONTROL_PLANE_MACHINE_TYPE:="Standard_D2s_v3"}"
export AZURE_NODE_MACHINE_TYPE="${AZURE_NODE_MACHINE_TYPE:="Standard_D2s_v3"}"

export KUBE_VERSION=""${KUBE_VERSION:="v1.26.6"}
export CLUSTER_API_VERSION="${CLUSTER_API_VERSION:="v1.5.1"}"
export AZURE_PROVIDER_VERSION="${AZURE_PROVIDER_VERSION:="v1.10.4"}"
export KIND_VERSION="${KIND_VERSION:="v0.20.0"}"
export CALICO_VERSION="${CALICO_VERSION:="v3.26.1"}"
