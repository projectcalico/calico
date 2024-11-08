export SUFFIX="${SUFFIX:=${USER}}"

export AZURE_LOCATION="${AZURE_LOCATION:="eastus2"}"
export AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:=rg-winfv-${SUFFIX}}"

#export AZURE_WINDOWS_IMAGE_SKU="${AZURE_WINDOWS_IMAGE_SKU:="2022-datacenter-core-g2"}"
#export AZURE_WINDOWS_IMAGE_VERSION="${AZURE_WINDOWS_IMAGE_VERSION:="20348.2402.240405"}"

export AZURE_WINDOWS_IMAGE_SKU="${AZURE_WINDOWS_IMAGE_SKU:="2019-datacenter-core-g2"}"
export AZURE_WINDOWS_IMAGE_VERSION="${AZURE_WINDOWS_IMAGE_VERSION:="17763.5696.240406"}"

export LINUX_NODE_COUNT="${LINUX_NODE_COUNT:=1}"
export WINDOWS_NODE_COUNT="${WINDOWS_NODE_COUNT:=1}"


# Get K8S_VERSION variable from metadata.mk, error out if it cannot be found
SCRIPT_CURRENT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
METADATAMK=${SCRIPT_CURRENT_DIR}/../../../../metadata.mk
if [ -f ${METADATAMK} ]; then
    K8S_VERSION_METADATA=$(grep K8S_VERSION ${METADATAMK} | cut -d "=" -f 2)
    if [[ ! ${K8S_VERSION_METADATA} =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Failed to retrieve K8S_VERSION from ${METADATAMK}"
        exit 1
    fi
else
    echo "Failed to open ${METADATAMK}"
    exit 1
fi
export KUBE_VERSION="${KUBE_VERSION:=${K8S_VERSION_METADATA#v}}"

export CONTAINERD_VERSION="${CONTAINERD_VERSION:="1.6.35"}"

export SSH_KEY_FILE="$PWD/.sshkey"
