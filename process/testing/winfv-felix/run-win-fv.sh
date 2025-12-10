#!/usr/bin/env bash
# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

# This is the entry point for Windows Felix FV test.

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REPO_DIR="${SCRIPT_DIR}/../../.."
export ASO_DIR="${SCRIPT_DIR}/../aso"
export UTILS_DIR="${SCRIPT_DIR}/../util"

. ${UTILS_DIR}/utils.sh

: "${FV_TYPE:?Error: FV_TYPE is not set}"

# Create cluster with one Linux node and one Windows node.
export LINUX_NODE_COUNT=1
export WINDOWS_NODE_COUNT=1

# Create kubeadm cluster
pushd "${ASO_DIR}"
make setup-kubeadm
make install-calico
popd

# Setup and run FV test
pushd "${SCRIPT_DIR}"
FV_TYPE=${FV_TYPE} ./setup-fv.sh | tee setupfv.log

# Copy report directory from windows node.
rm -r ./report || true
${ASO_DIR}/scp-from-windows.sh 0 'c:/k/report' ./report || true

pause-for-debug

# Get results and logs
ls -ltr ./report
mkdir -p /home/semaphore/fv.log
cp setupfv.log /home/semaphore/fv.log/ || true
cp ./report/*.log /home/semaphore/fv.log/ || true

# Print relevant snippets from logs
log_regexps='(?<!Decode)Failure|SUCCESS|FV-TEST-START'
compgen -G /home/semaphore/fv.log/*.log > /dev/null && \
for log_file in /home/semaphore/fv.log/*.log; do
    prefix="[$(basename ${log_file})]"
    cat ${log_file} | iconv -f UTF-16 -t UTF-8 | sed 's/\r$//g' | grep --line-buffered --perl ${log_regexps} -B 2 -A 15 | sed 's/.*/'"${prefix}"' &/g'
done;

# Search for the file indicates that the Windows node has completed the FV process
if [ ! -f ./report/done-marker ];
then
    echo "Windows node failed to complete the FV process."
    exit 1
fi

popd
echo "Windows Felix FV test completed."
