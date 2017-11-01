#!/bin/sh
# Initialize the host/node for use with flexvolume driver
FLEXVOL_HOME=/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds/
sudo mkdir -p ${FLEXVOL_HOME}
sudo cp flexvoldriver ${FLEXVOL_HOME}/uds
sudo mkdir -p /tmp/udsuspver/
sudo mkdir -p /tmp/nodeagent/
