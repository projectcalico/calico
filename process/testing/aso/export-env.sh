# Get the directory where this script is located (ASO directory)
ASO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify required environment variables
: "${AZURE_SUBSCRIPTION_ID:?Environment variable empty or not defined.}"
: "${AZURE_TENANT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_SECRET:?Environment variable empty or not defined.}"

export SUFFIX="${SUFFIX:=${USER}-aso}"

export AZURE_LOCATION="${AZURE_LOCATION:="eastus2"}"
export AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:=rg-winfv-${SUFFIX}}"

# Windows Server 2022 (latest version as of Nov 2025)
export AZURE_WINDOWS_IMAGE_SKU="${AZURE_WINDOWS_IMAGE_SKU:="2022-datacenter-core-g2"}"
export AZURE_WINDOWS_IMAGE_VERSION="${AZURE_WINDOWS_IMAGE_VERSION:="20348.4405.251112"}"
export WINDOWS_SERVER_VERSION="${WINDOWS_SERVER_VERSION:="windows-2022"}"

# Windows Server 2019 (legacy, use if 2022 has issues)
#export AZURE_WINDOWS_IMAGE_SKU="${AZURE_WINDOWS_IMAGE_SKU:="2019-datacenter-core-g2"}"
#export AZURE_WINDOWS_IMAGE_VERSION="${AZURE_WINDOWS_IMAGE_VERSION:="17763.5696.240406"}"
#export WINDOWS_SERVER_VERSION="${WINDOWS_SERVER_VERSION:="windows-2019"}"

export LINUX_NODE_COUNT="${LINUX_NODE_COUNT:=3}"
export WINDOWS_NODE_COUNT="${WINDOWS_NODE_COUNT:=2}"

# Verbose mode - set to "true" to see all command output, "false" to suppress output
export VERBOSE="${VERBOSE:="false"}"

export KUBE_VERSION="${KUBE_VERSION:="v1.33.6"}"

export CONTAINERD_VERSION="${CONTAINERD_VERSION:="1.7.22"}"

export SSH_KEY_FILE="${ASO_DIR}/.sshkey"

export GCR_IO_PULL_SECRET="${GCR_IO_PULL_SECRET:="${HOME}/secrets/docker_cfg.json"}"
export TSEE_TEST_LICENSE="${TSEE_TEST_LICENSE:="${HOME}/secrets/license.yaml"}"

export PRODUCT="calico"
export RELEASE_STREAM="master"
export HASH_RELEASE="true"
