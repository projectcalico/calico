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

set -o errexit
set -o nounset
set -o pipefail

set -e
LOCAL_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# scp from OpenSSH versions 8.8 and newer requires a '-O' flag in order to work correctly
# with windows ssh servers, but older versions don't know about that flag. Only use
# it when necessary (i.e. supported).
OFLAG="-O "
if [ "$(scp -O 2>&1 | grep -c 'unknown option -- O')" -gt 0 ]; then
    OFLAG=""
fi

: ${KUBECTL:=${LOCAL_PATH}/bin/kubectl}
: ${WIN_NODE_COUNT:=2}

KCAPZ="${KUBECTL} --kubeconfig=./kubeconfig"

APISERVER=$(${KCAPZ} config view -o jsonpath="{.clusters[?(@.name == \"${CLUSTER_NAME_CAPZ}\")].cluster.server}" | awk -F/ '{print $3}' | awk -F: '{print $1}')
if [ -z "${APISERVER}" ] ; then
  echo "Failed to get apiserver public ip"
  exit 1
fi
echo
echo APISERVER: ${APISERVER}

${KCAPZ} get node -o wide

echo
echo "Generating helper files"
CONNECT_FILE="ssh-node.sh"
echo "#---------Connect to Instance--------" | tee ${CONNECT_FILE}
echo "#usage: ./ssh-node.sh 6 to ssh into 10.1.0.6" | tee -a ${CONNECT_FILE}
echo "#usage: ./ssh-node.sh 6 'Get-Service -Name kubelet' > output" | tee -a ${CONNECT_FILE}
echo ssh -t -i ${LOCAL_PATH}/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i ${LOCAL_PATH}/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' capi@10.1.0.\$1 \$2 | tee -a ${CONNECT_FILE}
chmod +x ${CONNECT_FILE}
echo

SCP_FILE="scp-to-node.sh"
echo "#---------Copy files to Instance--------" | tee ${SCP_FILE}
echo "#usage: ./scp-to-node.sh 6 kubeconfig c:\\\\k\\\\kubeconfig -- copy kubeconfig to 10.1.0.6" | tee -a ${SCP_FILE}
echo "#usage: ./scp-to-node.sh 6 images/ebpf-for-windows-c-temp.zip 'c:\\' -- copy temp zip to 10.1.0.6" | tee -a ${SCP_FILE}
echo scp ${OFLAG} -i ${LOCAL_PATH}/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i ${LOCAL_PATH}/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' \$2 capi@10.1.0.\$1:\$3 | tee -a ${SCP_FILE}
chmod +x ${SCP_FILE}
echo

SCP_FROM_NODE="scp-from-node.sh"
echo "#---------Copy files from Instance--------" | tee ${SCP_FROM_NODE}
echo "#usage: ./scp-from-node.sh 6 c:/k/calico.log ./calico.log" | tee -a ${SCP_FROM_NODE}
echo scp ${OFLAG} -r -i ${LOCAL_PATH}/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i ${LOCAL_PATH}/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' capi@10.1.0.\$1:\$2 \$3 | tee -a ${SCP_FROM_NODE}
chmod +x ${SCP_FROM_NODE}

# Update env file with Windows ips
sed -i "/^export ID[0-9]=\"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\"/d" ./export-env.sh

IP0=`$KCAPZ get node win-p-win000000 -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'`
echo; echo "Windows nodes IPs"
echo "IP0: $IP0"

if [[ $WIN_NODE_COUNT -gt 1 ]]; then
  IP1=`$KCAPZ get node win-p-win000001 -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'`
  echo "IP1: $IP1"
fi
