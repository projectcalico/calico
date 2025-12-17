#!/usr/bin/env bash
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

# Recopy run-fv-cni-plugin.ps1 to Windows nodes and rerun the FV test.
# Useful for iterating on tests without rebuilding the cluster.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: ${ASO_DIR:=${SCRIPT_DIR}/../aso}

. ${ASO_DIR}/export-env.sh
. ${ASO_DIR}/vmss.sh info

: ${GOMPLATE:=${ASO_DIR}/bin/gomplate}
: ${BACKEND:?Error: BACKEND is not set}

# Kubeadm API server runs on port 6443
export APISERVER_PORT=6443

cd "${SCRIPT_DIR}"

# Generate and copy the run-fv script to Windows node
echo "Generating run-fv.ps1 with gomplate..."
mkdir -p ./windows
${GOMPLATE} --file ./run-fv-cni-plugin.ps1 --out ./windows/run-fv.ps1

echo "Copying run-fv.ps1 to Windows node..."
${ASO_DIR}/scp-to-windows.sh 0 ./windows/run-fv.ps1 'c:\k\run-fv.ps1'

# Kill any existing win-fv.exe processes and clean up old reports
echo "Killing any existing win-fv.exe processes..."
${WINDOWS_CONNECT_COMMAND} "Stop-Process -Name win-fv -Force -ErrorAction SilentlyContinue; Remove-Item -Path c:\\k\\report\\* -Force -ErrorAction SilentlyContinue"

# Run the FV test
echo "Running FV test with backend: ${BACKEND}..."
if [[ "$BACKEND" == "overlay" ]]; then
  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\run-fv.ps1 -Backend overlay"
elif [[ "$BACKEND" == "l2bridge" ]]; then
  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\run-fv.ps1 -Backend l2bridge"
else
  echo "Invalid BACKEND: $BACKEND. Use 'overlay' or 'l2bridge'."
  exit 1
fi

# Copy report from Windows node
echo "Copying report from Windows node..."
rm -rf ./report || true
${ASO_DIR}/scp-from-windows.sh 0 'c:/k/report' ./report || true

echo "FV test completed. Results in ./report/"
ls -la ./report/ || true

