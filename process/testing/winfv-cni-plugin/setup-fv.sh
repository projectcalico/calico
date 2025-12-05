#!/bin/bash
# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

: ${ASO_DIR:=${SCRIPT_DIR}/../aso}
: ${UTILS_DIR:=${SCRIPT_DIR}/../util}

. ${UTILS_DIR}/utils.sh
. ${ASO_DIR}/export-env.sh
. ${ASO_DIR}/vmss.sh info

: ${KUBECTL:=${ASO_DIR}/bin/kubectl}
: ${GOMPLATE:=${ASO_DIR}/bin/gomplate}
: ${BACKEND:?Error: BACKEND is not set}

# Kubeadm API server runs on port 6443
export APISERVER_PORT=6443

function create_l2bridge_network() {
  # Create external network will cause ssh session to hang.
  # Use timeout and ignore error state to make sure the script will 
  # keep running.
  set +e
  timeout -s SIGTERM 20s ${WINDOWS_CONNECT_COMMAND} "c:\\k\\create-network.ps1 -Backend l2bridge"
  set -e
}

function create_overlay_network() {
  set +e
  timeout -s SIGTERM 20s ${WINDOWS_CONNECT_COMMAND} "c:\\k\\create-network.ps1 -Backend overlay"
  set -e
}

function run_fv_l2bridge() {
  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\run-fv.ps1 -Backend l2bridge"
  echo
}

function run_fv_overlay() {
  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\run-fv.ps1 -Backend overlay"
  echo
}

function copy_run_fv_script_to_windows() {
  # Copy the run-fv script to Windows node
  mkdir -p ./windows
  ${GOMPLATE} --file ./run-fv-cni-plugin.ps1 --out ./windows/run-fv.ps1
  
  # Copy run-fv.ps1 to Windows node using ASO helper
  ${ASO_DIR}/scp-to-windows.sh 0 ./windows/run-fv.ps1 'c:\k\run-fv.ps1'
  echo "Copied run-fv.ps1 to Windows node"
}

# Main execution
copy_run_fv_script_to_windows

if [[ "$BACKEND" == "overlay" ]]; then
  create_overlay_network
  run_fv_overlay
elif [[ "$BACKEND" = "l2bridge" ]]; then
  create_l2bridge_network
  run_fv_l2bridge
else
  echo "Invalid network backend paramenter $BACKEND provided"
  exit -1
fi

