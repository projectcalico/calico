#!/usr/bin/env bash

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

. ../util/utils.sh

# Create cluster
make setup-kubeadm 

# Install Calico
make install-calico

pause-for-debug
