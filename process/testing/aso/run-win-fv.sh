#!/usr/bin/env bash

set -e
set -x

. ../util/utils.sh"

# Create cluster
make setup-kubeadm 

# Install Calico
make install-calico

pause-for-debug
