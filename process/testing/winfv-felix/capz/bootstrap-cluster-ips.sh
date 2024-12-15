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

: ${KUBECTL:=./bin/kubectl}
: ${KCAPZ:="${KUBECTL} --kubeconfig=./kubeconfig"}
: "${AZURE_RESOURCE_GROUP:?Environment variable empty or not defined.}"

CAPZ_CONTROL_PLANE_IP=$(az vm list-ip-addresses -g "$AZURE_RESOURCE_GROUP" | jq -r .[0].virtualMachine.network.privateIpAddresses[0])
echo; echo "Control Plane IP:" "$CAPZ_CONTROL_PLANE_IP"

vmss_length=$(az vmss list -g "$AZURE_RESOURCE_GROUP" | jq 'length')
LINUX_NAMES=""
WINDOWS_NAMES=""
i=0
while [[ $i -lt $vmss_length ]]; do
  vm=$(az vmss list -g "$AZURE_RESOURCE_GROUP" | jq ".[$i] | .name, .virtualMachineProfile.osProfile.linuxConfiguration.provisionVMAgent, .virtualMachineProfile.osProfile.windowsConfiguration.provisionVMAgent")
  name=$(echo $vm | cut -d" " -f1)
  is_linux=$(echo $vm | cut -d" " -f2)
  if [[ $is_linux == "true" ]]; then
    LINUX_NAMES="$LINUX_NAMES $(echo "$name" | tr -d '"')"
  fi
  is_windows=$(echo $vm | cut -d" " -f3)
  if [[ $is_windows == "true" ]]; then
    WINDOWS_NAMES="$WINDOWS_NAMES $(echo "$name" | tr -d '"')"
  fi
  i=$((i+1))
done

CAPZ_LINUX_IPS=""
for name in $LINUX_NAMES; do
  ip=$(az vmss nic list -g "$AZURE_RESOURCE_GROUP" --vmss-name "$name" | jq -r .[].ipConfigurations[].privateIPAddress)
  CAPZ_LINUX_IPS="$CAPZ_LINUX_IPS $ip"
done

echo; echo "Linux node IPs:" "$CAPZ_LINUX_IPS"

CAPZ_WINDOWS_IPS=""
for name in $WINDOWS_NAMES; do
  ip=$(az vmss nic list -g "$AZURE_RESOURCE_GROUP" --vmss-name "$name" | jq -r .[].ipConfigurations[].privateIPAddress)
  CAPZ_WINDOWS_IPS="$CAPZ_WINDOWS_IPS $ip"
done

echo; echo "Windows node IPs:" "$CAPZ_WINDOWS_IPS"

if [ !  -f ./ssh-node.sh ]; then
  echo "'./ssh-node.sh' helper not found"
  exit 1
fi

CAPZ_K8S_VERSION_MAJOR=$(${KCAPZ} version -o json | jq -r ".serverVersion.major")
CAPZ_K8S_VERSION_MINOR=$(${KCAPZ} version -o json | jq -r ".serverVersion.minor")

if [ "$CAPZ_K8S_VERSION_MAJOR" -eq 1 ] && [ "$CAPZ_K8S_VERSION_MINOR" -ge 29 ]; then
  echo "In kubernetes v1.29+, kubelet no longer sets up node IPs when using external cloud-provider."
  echo "See https://github.com/kubernetes/kubernetes/issues/120720 for more information."
else
  echo "Kubernetes version is lower than v1.29, no need for bootstrapping node IPs, exiting"
  exit 0
fi

echo; echo "Set up node IPs in kubelet config"

for linux_node_ip in $CAPZ_CONTROL_PLANE_IP $CAPZ_LINUX_IPS; do
  ./ssh-node.sh "$linux_node_ip" "cat /etc/default/kubelet"
  ./ssh-node.sh "$linux_node_ip" "sudo sh -c 'sed -i -e \"s/\$/ --node-ip=$linux_node_ip/\" /etc/default/kubelet; systemctl restart kubelet'"
  ./ssh-node.sh "$linux_node_ip" "cat /etc/default/kubelet"
done

for windows_node_ip in $CAPZ_WINDOWS_IPS; do
  ./ssh-node.sh "$windows_node_ip" "\$file = (get-content C:/k/StartKubelet.ps1); echo \$file"
  if [ "$WINDOWS_SERVER_VERSION" == "windows-2022" ]; then
    ./ssh-node.sh "$windows_node_ip" "\$regex = '^\\\$kubeletCommandLine = .*';  \$line = ((get-content C:/k/StartKubelet.ps1) | select-string \$regex); (get-content C:/k/StartKubelet.ps1) -replace \$regex, (\$line.ToString() + ' + \\\" --node-ip=$windows_node_ip\\\"') | set-content c:/k/StartKubelet.ps1; restart-service kubelet"
  else #"$WINDOWS_SERVER_VERSION" == "windows-2019"
    ./ssh-node.sh "$windows_node_ip" "\$regex = '^\\\$kubeletCommandLine = .*';  \$line = ((get-content C:/k/StartKubelet.ps1) | select-string \$regex); (get-content C:/k/StartKubelet.ps1) -replace \$regex, (\$line.ToString() + ' + \\\"\\\"\\\" --node-ip=$windows_node_ip\\\"\\\"\\\"') | set-content -path c:/k/StartKubelet.ps1; restart-service kubelet"
  fi
  ./ssh-node.sh "$windows_node_ip" "\$file = (get-content C:/k/StartKubelet.ps1); echo \$file"
done

echo "Done bootstrapping node IPs"
