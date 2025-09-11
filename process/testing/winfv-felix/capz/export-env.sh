export CLUSTER_NAME_CAPZ="${CLUSTER_NAME_CAPZ:=${USER}-capz-win}"
export AZURE_LOCATION="${AZURE_LOCATION:="westus2"}"

# [Optional] Select resource group. The default value is ${CLUSTER_NAME_CAPZ}-rg.
export AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:=${CLUSTER_NAME_CAPZ}-rg}"

# These are required by the machinepool-windows template
export CI_RG="${AZURE_RESOURCE_GROUP}-ci"
export USER_IDENTITY="cloud-provider-user-identity"

# Optional, can be windows-2019 (default) or windows-2022
# https://capz.sigs.k8s.io/developers/development.html
# https://github.com/kubernetes-sigs/cluster-api-provider-azure/blob/main/templates/flavors/machinepool-windows/machine-pool-deployment-windows.yaml#L29
# Default changed to 2019 due to this 2022 issue: https://github.com/microsoft/Windows-Containers/issues/516
export WINDOWS_SERVER_VERSION="${WINDOWS_SERVER_VERSION:="windows-2019"}"

# Select VM types ("Standard_D2s_v3" is recommented for OSS Calico)
export AZURE_CONTROL_PLANE_MACHINE_TYPE="${AZURE_CONTROL_PLANE_MACHINE_TYPE:="Standard_D2s_v3"}"
export AZURE_NODE_MACHINE_TYPE="${AZURE_NODE_MACHINE_TYPE:="Standard_D2s_v3"}"

# Retrieve KUBE_VERSION and KIND_VERSION from metadata.mk
SCRIPT_CURRENT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
METADATAMK=${SCRIPT_CURRENT_DIR}/../../../metadata.mk
if [ -f ${METADATAMK} ]; then
    KINDEST_NODE_VERSION_METADATA=$(grep 'KINDEST_NODE_VERSION=' ${METADATAMK} | cut -d "=" -f 2)
    KIND_VERSION_METADATA=$(grep 'KIND_VERSION=' ${METADATAMK} | cut -d "=" -f 2)
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

# Azure image versions use versions corresponding to kubernetes versions, e.g. 129.7.20240717 corresponds to k8s v1.29.7
AZ_VERSION="$(az vm image list --publisher cncf-upstream --offer capi --all -o json | jq '.[-1].version' -r)"
export AZ_KUBE_VERSION="v${AZ_VERSION:0:1}"."${AZ_VERSION:1:2}".$(echo "${AZ_VERSION}" | cut -d'.' -f2)

export CLUSTER_API_VERSION="${CLUSTER_API_VERSION:="v1.11.1"}"
export AZURE_PROVIDER_VERSION="${AZURE_PROVIDER_VERSION:="v1.21.0"}"
export CONTAINERD_VERSION="${CONTAINERD_VERSION:="v1.7.22"}"
export YQ_VERSION="${YQ_VERSION:="v4.44.5"}"
