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

# Step 1: Create kubeadm cluster
cd "${ASO_DIR}"
make setup-kubeadm

# Step 3: Setup and run FV test
cd "${SCRIPT_DIR}"
BACKEND=${BACKEND} ./setup-fv.sh

# Copy report directory from windows.
rm -r ./report || true
${ASO_DIR}/scp-from-windows.sh 0 'c:\k\report' ./report

echo "Windows CNI-Plugin FV test completed."
pause-for-debug
