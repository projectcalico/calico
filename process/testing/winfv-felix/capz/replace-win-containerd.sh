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

. ./utils.sh

# Use KUBECTL to access the local kind management cluster. Use KCAPZ to
# access the CAPZ cluster.
: ${KUBECTL:=./bin/kubectl}
: ${KCAPZ:="${KUBECTL} --kubeconfig=./kubeconfig"}
: ${CONTAINERD_VERSION:="v1.7.22"}

# Cordon+drain windows nodes, then run the powershell script that replaces
# containerd with the specific version wanted and finally uncordon the nodes

echo "Installing containerd ${CONTAINERD_VERSION} on windows nodes"

${KCAPZ} cordon -l kubernetes.io/os=windows
${KCAPZ} drain -l kubernetes.io/os=windows --ignore-daemonsets
WIN_NODES=$(${KCAPZ} get nodes -o wide -l kubernetes.io/os=windows --no-headers | awk '{print $6}' | sort)
for n in ${WIN_NODES}
do
  ./scp-to-node.sh $n ./replace-win-containerd.ps1 c:\\k\\replace-win-containerd.ps1
  ./ssh-node.sh $n "c:\\k\\replace-win-containerd.ps1 -ContainerdVersion ${CONTAINERD_VERSION#"v"}"
done
${KCAPZ} uncordon -l kubernetes.io/os=windows

echo "Done installing containerd ${CONTAINERD_VERSION} on windows nodes"
