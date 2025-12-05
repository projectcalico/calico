#!/usr/bin/env bash

# This is entry point for Windows CNI-Plugin FV test.

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ASO_DIR="${SCRIPT_DIR}/../aso"
export UTILS_DIR="${SCRIPT_DIR}/../util"

. ${UTILS_DIR}/utils.sh

: ${BACKEND:?Error: BACKEND is not set}

# Create cluster with one Linux node and one Windows node.
export LINUX_NODE_COUNT=1
export WINDOWS_NODE_COUNT=1
export VERBOSE=true # Enable verbose output for debugging as nodes count is small.

# Create kubeadm cluster
cd "${ASO_DIR}"
make setup-kubeadm

# Install Calico
make install-calico

# Setup and run FV test
cd "${SCRIPT_DIR}"
BACKEND=${BACKEND} ./setup-fv.sh | tee setupfv.log

# Copy report directory from windows node.
rm -r ./report || true
${ASO_DIR}/scp-from-windows.sh 0 'c:\k\report' ./report || true

pause-for-debug

# Get results and logs
ls -ltr ./report
mkdir /home/semaphore/fv.log
cp setup-fv.log /home/semaphore/setup-fv.log
cp ./report/*.log /home/semaphore/fv.log

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

echo "Windows CNI-Plugin FV test completed."
