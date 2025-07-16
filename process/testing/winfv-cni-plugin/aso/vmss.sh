#!/bin/bash
# Copyright (c) 2024 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

. ./export-env.sh

. ./utils.sh

: ${KUBECTL:=./bin/kubectl}
: ${GOMPLATE:=./bin/gomplate}

function apply_azure_crds() {
  # Generate and export a secure password for Windows RDP.
  export PASSWORD=$(openssl rand -base64 16)
  export PASSWORD_BASE64=$(echo -n "$PASSWORD" | base64)
  cat << EOF > password.txt
-------------Connect to Windows Instances-------------
username: winfv 
password: $PASSWORD
password-base64: $PASSWORD_BASE64
EOF

  rm ${SSH_KEY_FILE} || true
  ssh-keygen -m PEM -t rsa -b 2048 -f "${SSH_KEY_FILE}" -N '' -C "" 1>/dev/null
  echo "Machine SSH key generated in ${SSH_KEY_FILE}"
  export PUBLIC_KEY=$(cat ${SSH_KEY_FILE}.pub)

  rm -rf infra/manifests || true
  ${GOMPLATE} --input-dir infra/templates --output-dir infra/manifests

  ${KUBECTL} apply -f infra/manifests/resource-group.yaml
  ${KUBECTL} apply -f infra/manifests/password.yaml
  ${KUBECTL} apply -f infra/manifests/vnet.yaml
  ${KUBECTL} apply -f infra/manifests/security-group.yaml
  ${KUBECTL} apply -f infra/manifests/vmss-linux.yaml
  ${KUBECTL} apply -f infra/manifests/vmss-windows.yaml
}

function delete_azure_crds() {
  ${KUBECTL} delete ns winfv
}

function show_connections() {
  # Wait for vmss deployments
  echo; echo "show_connections started..."
  echo "Wait for vmss-linux to be ready ..."
  ${KUBECTL} wait --for=condition=Ready --timeout=8m -n winfv virtualmachinescalesets vmss-linux
  LINUX_INSTANCE_ID=$(az vmss list-instances --name vmss-linux --resource-group $AZURE_RESOURCE_GROUP --query "[0].instanceId" | sed 's/"//g')
  LINUX_EIP=$(az vmss list-instance-public-ips --name vmss-linux --resource-group $AZURE_RESOURCE_GROUP --query "[0].ipAddress" | sed 's/"//g')
  LINUX_PIP=$(az vmss nic list-vm-nics --vmss-name vmss-linux --resource-group $AZURE_RESOURCE_GROUP --instance-id $LINUX_INSTANCE_ID --query "[0].ipConfigurations[0].privateIPAddress" | sed 's/"//g')
  echo "vmss-linux is ready. PIP:$LINUX_PIP, EIP:$LINUX_EIP"

  echo "Wait for vmss-windows to be ready ..."
  ${KUBECTL} wait --for=condition=Ready --timeout=8m -n winfv virtualmachinescalesets vmss-windows
  WINDOWS_INSTANCE_ID=$(az vmss list-instances --name vmss-windows --resource-group $AZURE_RESOURCE_GROUP --query "[0].instanceId" | sed 's/"//g')
  WINDOWS_EIP=$(az vmss list-instance-public-ips --name vmss-windows --resource-group $AZURE_RESOURCE_GROUP --query "[0].ipAddress" | sed 's/"//g')
  WINDOWS_PIP=$(az vmss nic list-vm-nics --vmss-name vmss-windows --resource-group $AZURE_RESOURCE_GROUP --instance-id $WINDOWS_INSTANCE_ID --query "[0].ipConfigurations[0].privateIPAddress" | sed 's/"//g')
  echo "vmss-windows is ready. PIP:$WINDOWS_PIP, EIP:$WINDOWS_EIP"

  # Setup connection info
  MASTER_CONNECT_COMMAND="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${LINUX_EIP}"
  WINDOWS_CONNECT_COMMAND="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${WINDOWS_EIP} powershell"

  WIN_PASSWORD=$(grep "password:" ./password.txt | awk -F':' '{print $2}')

  cat << EOF > connect.txt
-------------Connect to Linux Master Instances--------
${MASTER_CONNECT_COMMAND}

-------------Connect to Windows Instances-------------
RDP://${WINDOWS_EIP} user: winfv password:$WIN_PASSWORD
${WINDOWS_CONNECT_COMMAND}
EOF

  export LINUX_EIP LINUX_PIP WINDOWS_EIP WINDOWS_PIP MASTER_CONNECT_COMMAND WINDOWS_CONNECT_COMMAND CONTAINERD_VERSION

  echo
  echo "Generating helper files"
  echo ${MASTER_CONNECT_COMMAND} > ./ssh-node-linux.sh
  chmod +x ./ssh-node-linux.sh

  cat << EOF > ssh-node-windows.sh
#usage: . /ssh-node-windows.sh "Restart-Computer -force"
${WINDOWS_CONNECT_COMMAND} \$1
EOF
  chmod +x ./ssh-node-windows.sh

  cat << EOF > scp-to-windows.sh
#---------Copy files to windows--------
#usage: ./scp-to-windows.sh kubeconfig c:\\\\k\\\\kubeconfig
#usage: ./scp-to-windows.sh images/ebpf-for-windows-c-temp.zip 'c:\\'
scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \$1 winfv@${WINDOWS_EIP}:\$2
EOF
chmod +x ./scp-to-windows.sh


  cat << EOF > scp-from-windows.sh
#---------Copy files from windows--------
#usage: ./scp-from-windows.sh c:\\k\\calico.log ./calico.log
scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no winfv@${WINDOWS_EIP}:\$1 \$2
EOF
chmod +x ./scp-from-windows.sh

  pause-for-debug
  echo "show_connections done."; echo
}

function retry-ssh() {
  local SSH_CMD=$1
  local RETRY_INTERVAL=30         # Seconds between retries
  local MAX_DURATION=300

  # Tracking time
  START_TIME=$(date +%s)

  while true; do
    echo "Attempting $SSH_CMD..."
    if $SSH_CMD; then
        echo "SSH command succeeded."
        return 0
    else
        echo "SSH command failed. Running show_connections and retrying in $RETRY_INTERVAL seconds..."
        show_connections  # Replace with your actual command or function
    fi

    sleep $RETRY_INTERVAL

    CURRENT_TIME=$(date +%s)
    ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

    if [ $ELAPSED_TIME -ge $MAX_DURATION ]; then
        echo "Timeout reached after $((MAX_DURATION / 60)) minutes. Giving up."
        exit 1
    fi
  done
}

# Azure may assign a different public IP to a VM even after it is marked as ready.
# This function attempts to SSH into the VM multiple times to ensure it is accessible.
function confirm-nodes-ssh() {
  echo;echo "confirm nodes can be accessed by ssh..."
  show_connections
  retry-ssh "${MASTER_CONNECT_COMMAND} echo"
  retry-ssh "${WINDOWS_CONNECT_COMMAND} -Command 'echo'"

  # Azure may assign another public IP to the VM.
  # So even the first batch of SSHes works, the ip could be updated later.
  # Sleep and retry.
  echo "sleep 30 seconds..."
  sleep 30
  show_connections
  retry-ssh "${MASTER_CONNECT_COMMAND} echo"
  retry-ssh "${WINDOWS_CONNECT_COMMAND} -Command 'echo'"
  echo "VMs can be accessed by ssh.";echo
}

function parse_options() {
  usage() {
    cat <<HELP_USAGE
Usage: $(basename "$0")
          [-c]                # create azure resources
          [-o]                # ouput vmss connect information
          [-u]                # delete azure resources
          [-h]                # Print usage

HELP_USAGE
    exit 1
  }

  local OPTIND
  while getopts "chou" opt; do
    case ${opt} in
      o ) 
           show_connections
           ;;
      c )  apply_azure_crds;;
      u )  delete_azure_crds;;
      h )  usage;;
      \? ) usage;;
    esac
  done
  shift $((OPTIND -1))
}

case $1 in
  create)
    apply_azure_crds
    ;;
  info)
    show_connections
    ;;
  confirm-ssh)
    confirm-nodes-ssh
    ;;
  *)
    echo "vmss.sh [create|info|confirm-ssh]"
    ;;
esac

