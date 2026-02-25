# Warning: This file is not quite a shell script.  Semaphore executes the commands
# in this file by: splitting the file into lines; writing each line to a file;
# sourcing the files one at a time into a single shell session.  It wraps each
# command with something like this:
#
#   echo 'start-marker'; <command>; echo 'end-marker'
#
# Semaphore requires the end-marker to be emitted even if <command> fails.
# Hence, since our command runs in the same shell, it is not safe to do any
# of the following in this file:
#
# - "set -e" because, if <command> fails then "echo 'end-marker'" won't run.
# - "exit"   because it will exit the long-lived shell, which doesn't belong to us.
# - Use a multi-line if/while/for/etc because Semaphore splits the file on line.

# Enable pipefail so that we can use the pattern "<some command> | tee <logfile>"
# and get the return code from <some command> rather than tee.  This shouldn't
# interfere with Semaphore's logic since it doesn't use a pipeline.
set -o pipefail

echo "[INFO] starting prologue"

echo "[INFO] Clean out language tools we don't use to free up disk"
sudo rm -rf ~/{.kerl,.kiex,.npm,.nvm,.phpbrew,.rbenv,.sbt} /opt/{apache-maven*,firefox*,scala} /usr/lib/jvm /usr/local/{aws2,golang,phantomjs*} /root/.local/share/heroku /usr/local/lib/heroku

echo "[INFO] overriding DNS..."
echo "nameserver 208.67.222.222" | sudo tee /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf

echo "[INFO] checkout..."
checkout

echo "[INFO] stagger start time by 1 to 60s..."
sleep $((RANDOM % 60))

chmod 0600 ~/.keys/*
ssh-add ~/.keys/*

echo "[INFO] generating random token for unique cluster name..."
RANDOM_TOKEN1=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 4 || true)
RANDOM_TOKEN2=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 4 || true)
echo "[INFO] random tokens: ${RANDOM_TOKEN1} ${RANDOM_TOKEN2}"

echo "[INFO] Installing jq..."
sudo apt-get -o Acquire::Retries=5 update  -y
sudo apt-get install -o Acquire::Retries=5 jq -y

echo "[INFO] exporting default env vars..."
export SEMAPHORE_PIPELINE_STARTED_AT=$(date +%s)
export PROVISIONER=${PROVISIONER:-"gcp-kubeadm"}
export INSTALLER=${INSTALLER:-"manual"}
export DATAPLANE=${DATAPLANE:-"CalicoIptables"}  # Temporarily set all runs which don't specify a DATAPLANE to iptables.
export PRODUCT=${PRODUCT:-calico}
export TEST_TYPE=${TEST_TYPE:-k8s-e2e}
export NUM_INFRA_NODES=${NUM_INFRA_NODES:-0}
export SEMAPHORE_ARTIFACT_EXPIRY=${SEMAPHORE_ARTIFACT_EXPIRY:-2w}
export GOOGLE_PROJECT=${GOOGLE_PROJECT:-unique-caldron-775}
export GOOGLE_REGIONS=("us-central1" "us-west1")
export GOOGLE_REGION=${GOOGLE_REGION:-${GOOGLE_REGIONS[RANDOM%${#GOOGLE_REGIONS[@]}]}}
export GOOGLE_NETWORK=${GOOGLE_NETWORK:-semaphore-autotest}
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}
export AZ_LOCATION=${AZ_LOCATION:-eastus2}
export AZ_PROJECT=${AZ_PROJECT:-tigera-dev-ci}
export K8S_VERSION=${K8S_VERSION:-stable-3}
export KOPS_VERSION=${KOPS_VERSION:-$(curl --retry 9 --retry-all-errors -fsSL https://${GITHUB_ACCESS_TOKEN}:@api.github.com/repos/kubernetes/kops/releases/latest | jq -r '.tag_name')}
export KOPS_STATE_STORE_NAME=${KOPS_STATE_STORE_NAME:-kops-tigera-dev-ci}
export KOPS_AWS_DNS_ZONE=${KOPS_AWS_DNS_ZONE:-kops.ci.aws.eng.tigera.net}
export OPENSHIFT_BASE_DOMAIN=${OPENSHIFT_BASE_DOMAIN:-openshift.ci.aws.eng.tigera.net}
export RKE_VERSION=${RKE_VERSION:-$(curl --retry 9 --retry-all-errors -fsSL https://${GITHUB_ACCESS_TOKEN}:@api.github.com/repos/rancher/rke/releases | jq -r '.[].tag_name' | grep -v "rc" | sort -V | tail -1)}
export DOCKER_EE_VERSION=${DOCKER_EE_VERSION:-"19.03"}
export DOCKER_EE_RELEASE=${DOCKER_EE_RELEASE:-"5:19.03.8~3-0~ubuntu-xenial"}
export DOCKER_UCP_VERSION=${DOCKER_UCP_VERSION:-"3.3.0"}
export ENABLE_ALP=${ENABLE_ALP:-"false"}
export USE_HASH_RELEASE=${USE_HASH_RELEASE:-"true"}
export USE_LATEST_RELEASE=${USE_LATEST_RELEASE:-"false"}
export RELEASE_STREAM=${RELEASE_STREAM:-master}
export K8S_E2E_EXTRA_FLAGS=${K8S_E2E_EXTRA_FLAGS:-" --e2ecfg.calicoctl-opensource-image=calico/ctl:release-${RELEASE_STREAM} "}
export HELM_PATCH=${HELM_PATCH:-"0"}
export CALICOCTL_INSTALL_TYPE=${CALICOCTL_INSTALL_TYPE:-"binary"}
export BZ_LOGS_DIR=${BZ_LOGS_DIR:-$HOME/.bz/logs}
export BZ_HOME=${BZ_HOME:-"${HOME}/${SEMAPHORE_JOB_ID}"}
export BZ_LOCAL_DIR=${BZ_LOCAL_DIR:-"${BZ_HOME}/.local"}
export REPORT_DIR=${REPORT_DIR:-"${BZ_LOCAL_DIR}/report/${TEST_TYPE}"}
export BZ_GLOBAL_BIN=${BZ_GLOBAL_BIN:-$HOME/.local/bin}
export BZ_PATH=${BZ_PATH:-"${BZ_GLOBAL_BIN}/bz"}
export BZ_SECRETS_PATH=${BZ_SECRETS_PATH:-"$HOME/secrets"}
export BZ_PROFILES_PATH="${BZ_PROFILES_PATH:-$BZ_HOME}"
export BZ_MCM_PREFIX=${BZ_MCM_PREFIX:-"bz-${PRODUCT}-${RANDOM_TOKEN2}"}

export CLUSTER_NAME=${CLUSTER_NAME:-bz-${PRODUCT}-${RANDOM_TOKEN1}}
export DIAGS_ARCHIVE_FILENAME=${DIAGS_ARCHIVE_FILENAME:-${PROVISIONER}-${CLUSTER_NAME}-diags.tgz}
export BANZAI_CORE_BRANCH=${BANZAI_CORE_BRANCH:-""}
export BZ_TASK_VERSION=${BZ_TASK_VERSION:-"v2.8.1"}
export SEMAPHORE_AGENT_UPLOAD_JOB_LOGS=${SEMAPHORE_AGENT_UPLOAD_JOB_LOGS:-"when-trimmed"}

export RELEASE_STREAM=${RELEASE_STREAM:-master}

if [[ "${BANZAI_CORE_BRANCH}" != "" ]]; then BANZAI_CORE_BRANCH="--core-branch ${BANZAI_CORE_BRANCH}"; fi

mkdir -p "${BZ_GLOBAL_BIN}"
export PATH="${BZ_GLOBAL_BIN}:${PATH}"

echo "[INFO] Print Semaphore system information"
echo "[INFO] Print Memory information"
cat /proc/meminfo
echo "-----------"
echo "[INFO] Print CPU information"
cat /proc/cpuinfo
echo "-----------"
echo "Semaphore OS information"
lsb_release -a

echo "[INFO] installing google cloud sdk..."
gcloud_cmd_c1="echo \"deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main\" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list"
gcloud_cmd_c1="$gcloud_cmd_c1 && curl --retry 9 --retry-all-errors -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg"
if [[ $SEMAPHORE_AGENT_MACHINE_TYPE =~ ^c1-.* ]]; then eval "$gcloud_cmd_c1"; fi
sudo apt-get -o Acquire::Retries=5 update  -y || true; sudo apt-get install -o Acquire::Retries=5 google-cloud-cli google-cloud-cli-gke-gcloud-auth-plugin -y || true

echo "[INFO] activating google service account..."
export GOOGLE_APPLICATION_CREDENTIALS=${GOOGLE_APPLICATION_CREDENTIALS:-$HOME/secrets/banzai-google-service-account.json}
gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}"
gcloud config set project ${GOOGLE_PROJECT}
export GOOGLE_ZONE=${GOOGLE_ZONE:-$(gcloud compute zones list --filter="region~'$GOOGLE_REGION'" --format="value(name)" | awk 'BEGIN {srand()} {a[NR]=$0} rand() * NR < 1 {zone=$0} END {print zone}')}

# Update package lists to ensure the latest versions are available.
# Temporarily disable needrestart during installation to avoid interactive prompts.
# Set needrestart to automatically restart all required services after installation.
# Install python3-pip without requiring manual confirmation (-y flag).
# Explicitly restart all necessary services using needrestart to ensure daemons using outdated libraries are refreshed.
pip_install_cmd="echo \"[INFO] installing pip beforehand for c1...\""
pip_install_cmd="$pip_install_cmd; echo \"[INFO] Installing pip3...\" && sudo apt-get -o Acquire::Retries=5 update  && sudo NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=a apt-get install -o Acquire::Retries=5 python3-pip -y && sudo needrestart -r a"
if [[ $SEMAPHORE_AGENT_MACHINE_TYPE =~ ^c1-.* && $SEMAPHORE_AGENT_MACHINE_OS_IMAGE == "ubuntu2204" ]]; then eval "$pip_install_cmd"; fi

aws_cli_cmd="echo \"[INFO] installing AWS CLI using pip3...\""
aws_cli_cmd="$aws_cli_cmd; pip3 install --retries=20 --upgrade --user awscli"
if [[ $PROVISIONER =~ ^aws-.* ]]; then eval "$aws_cli_cmd"; fi

azure_cli_cmd="echo \"[INFO] installing Azure CLI...\""
azure_cli_cmd="$azure_cli_cmd; pip3 install --retries=20 azure-mgmt-core==1.5.0"  # Workaround from https://github.com/Azure/azure-cli/issues/31362
azure_cli_cmd="$azure_cli_cmd; curl --retry 9 --retry-all-errors -sfL https://aka.ms/InstallAzureCLIDeb | sudo bash"
azure_cli_cmd="$azure_cli_cmd; az login --service-principal -u ${AZ_SP_ID} -p ${AZ_SP_PASSWORD} --tenant ${AZ_TENANT_ID}"
if [[ $PROVISIONER =~ ^azr-.* ]]; then eval "$azure_cli_cmd"; fi

install_tools_cmd="echo \"[INFO] installing addtional tools for c1...\""
install_tools_cmd="$install_tools_cmd; echo \"[INFO] Installing unzip...\" && sudo NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=a apt-get install -o Acquire::Retries=5 unzip -y && sudo needrestart -r a"
install_tools_cmd="$install_tools_cmd; echo \"[INFO] Installing requests...\" && pip3 install --retries=20 --upgrade requests"
if [[ $SEMAPHORE_AGENT_MACHINE_TYPE =~ ^c1-.* ]]; then eval "$install_tools_cmd"; fi

if [[ "$CREATE_WINDOWS_NODES" == "true" ]]; then echo "[INFO] Installing putty-tools..."; sudo NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=a apt-get install -o Acquire::Retries=5 -y putty-tools && sudo needrestart -r a; fi

echo "[INFO] Installing Banzai CLI..."
[[ -n "${BZ_VERSION}" ]] && export BZ_RELEASE=tags/${BZ_VERSION} || export BZ_RELEASE=latest
export BZ_ASSET_ID=$(curl --retry 9 --retry-all-errors -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" -H "Accept: application/vnd.github.v3.raw" -s https://api.github.com/repos/${BZ_REPO}/releases/${BZ_RELEASE} | jq '.assets[] | select(.name|test("^bz.*linux-amd64"))| .id')
wget -q --auth-no-challenge --header='Accept:application/octet-stream' https://${GITHUB_ACCESS_TOKEN}:@api.github.com/repos/${BZ_REPO}/releases/assets/${BZ_ASSET_ID} -O "${BZ_GLOBAL_BIN}/bz"
chmod +x "${BZ_GLOBAL_BIN}/bz"

mkdir -p "$HOME/.docker"
cp ~/secrets/docker_cfg.json "$HOME/.docker/config.json"

mkdir -p "${BZ_LOGS_DIR}"

cd "$HOME" || exit
hcp_scripts="echo \"[INFO] Initializing Banzai utilities...\""
hcp_scripts="$hcp_scripts; git clone git@github.com:tigera/banzai-utils.git \"${HOME}/banzai-utils\""
hcp_scripts="$hcp_scripts; cp -R \"${HOME}/banzai-utils\"/ocp-hcp/*.sh \"${BZ_GLOBAL_BIN}\""
if [[ "${HCP_ENABLED}" == "true" ]]; then eval $hcp_scripts; fi

std="echo \"[INFO] Initializing Banzai profile...\""
std="$std; bz init profile -n ${SEMAPHORE_JOB_ID} --skip-prompt ${BANZAI_CORE_BRANCH} --secretsPath $HOME/secrets 2>&1 | tee >(gzip --stdout > ${BZ_LOGS_DIR}/initialize.log.gz)"
std="$std; cache store ${SEMAPHORE_JOB_ID} ${BZ_HOME}"

hcp="unset CLUSTER_NAME; unset DIAGS_ARCHIVE_FILENAME; unset K8S_VERSION"
hcp="$hcp; echo \"[INFO] starting hcp init...\""
hcp="$hcp; hcp-init.sh 2>&1 | tee \"${BZ_LOGS_DIR}/initialize.log\""
hcp="$hcp; cache store ${SEMAPHORE_JOB_ID} ${BZ_HOME}"

restore_hcp_hosting="echo \"[INFO] Restoring from ${SEMAPHORE_WORKFLOW_ID}-hosting-${HOSTING_CLUSTER} cache\""
restore_hcp_hosting="$restore_hcp_hosting; cache restore ${SEMAPHORE_WORKFLOW_ID}-hosting-${HOSTING_CLUSTER} |& tee ${BZ_LOGS_DIR}/restore.log"

if [[ "${HCP_ENABLED}" == "true" ]]; then std=$hcp; elif [[ "${HCP_STAGE}" == "hosting" || "${HCP_STAGE}" == "destroy-hosting" ]]; then std=$restore_hcp_hosting; fi
echo "$std"; eval "$std"

restore_hcp_hosting_home="echo \"[INFO] Setting BZ_HOME env var from restored cache\""
restore_hcp_hosting_home="$restore_hcp_hosting_home; unset BZ_HOME; export BZ_HOME=$(cat ${BZ_LOGS_DIR}/restore.log | grep -oP 'Restored: \K(.*)(?=.)' || echo '')"
if [[ "${HCP_STAGE}" == "hosting" || "${HCP_STAGE}" == "destroy-hosting" ]]; then echo "$restore_hcp_hosting_home"; eval "$restore_hcp_hosting_home"; fi

if [[ "${HCP_STAGE}" == "hosting" || "${HCP_STAGE}" == "destroy-hosting" ]]; then python3 -m pip install -r ${BZ_HOME}/scripts/requirements.txt; export PROVISIONER=aws-openshift; pip3 install --upgrade --user awscli; fi
export BZ_LOCAL_DIR=${BZ_LOCAL_DIR:-"${BZ_HOME}/.local"}

if [[ "${HCP_STAGE}" == "hosted" ]]; then artifact pull workflow hosting-${HOSTING_CLUSTER}-kubeconfig -f --destination ${BZ_LOCAL_DIR}/hosting-kubeconfig; fi

rm_firmware_cmd="echo \"[INFO] Removing /usr/lib/firmware to free disk space\""
rm_firmware_cmd="$rm_firmware_cmd; sudo rm -rf /usr/lib/firmware"
if [[ "${HCP_STAGE}" == "hosted" ]]; then echo "$rm_firmware_cmd"; eval "$rm_firmware_cmd"; fi

echo "[INFO] exiting prologue"
