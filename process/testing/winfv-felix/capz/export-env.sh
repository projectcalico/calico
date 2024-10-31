export CLUSTER_NAME_CAPZ="${CLUSTER_NAME_CAPZ:=${USER}-capz-win}"
export AZURE_LOCATION="${AZURE_LOCATION:="westus2"}"

# [Optional] Select resource group. The default value is ${CLUSTER_NAME_CAPZ}-rg.
export AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:=${CLUSTER_NAME_CAPZ}-rg}"
# These are required by the machinepool-windows template
export CI_RG="${AZURE_RESOURCE_GROUP}-ci"
export USER_IDENTITY="cloud-provider-user-identity"

# Optional, can be windows-2019 or windows-2022 (default)
# https://capz.sigs.k8s.io/developers/development.html
# https://github.com/kubernetes-sigs/cluster-api-provider-azure/blob/main/templates/flavors/machinepool-windows/machine-pool-deployment-windows.yaml#L29
export WINDOWS_SERVER_VERSION="${WINDOWS_SERVER_VERSION:="windows-2022"}"

# Select VM types ("Standard_D2s_v3" is recommented for OSS Calico)
export AZURE_CONTROL_PLANE_MACHINE_TYPE="${AZURE_CONTROL_PLANE_MACHINE_TYPE:="Standard_D2s_v3"}"
export AZURE_NODE_MACHINE_TYPE="${AZURE_NODE_MACHINE_TYPE:="Standard_D2s_v3"}"

# Retrieve KUBE_VERSION and KIND_VERSION from metadata.mk
SCRIPT_CURRENT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
METADATAMK=${SCRIPT_CURRENT_DIR}/../../../metadata.mk
if [ -f ${METADATAMK} ]; then
    KINDEST_NODE_VERSION_METADATA=$(grep KINDEST_NODE_VERSION ${METADATAMK} | cut -d "=" -f 2)
    KIND_VERSION_METADATA=$(grep KIND_VERSION ${METADATAMK} | cut -d "=" -f 2)
    if [[ ! ${KINDEST_NODE_VERSION_METADATA} =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ ! ${KIND_VERSION_METADATA} =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Failed to retrieve KINDEST_NODE_VERSION and/or KIND_VERSION from ${METADATAMK}"
        exit 1
    fi
else
    echo "Failed to open ${METADATAMK}"
    exit 1
fi

export KUBE_VERSION="${KINDEST_NODE_VERSION_METADATA}"
export KIND_VERSION="${KIND_VERSION_METADATA}"

export CLUSTER_API_VERSION="${CLUSTER_API_VERSION:="v1.7.7"}"
export AZURE_PROVIDER_VERSION="${AZURE_PROVIDER_VERSION:="v1.16.3"}"
export CONTAINERD_VERSION="${CONTAINERD_VERSION:="v1.7.22"}"
export YQ_VERSION="${YQ_VERSION:="v4.44.3"}"
