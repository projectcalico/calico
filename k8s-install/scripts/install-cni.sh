#!/bin/sh

# Script to install Calico CNI on a Kubernetes host.
# - Expects the host CNI binary path to be mounted at /host/opt/cni/bin.
# - Expects the host CNI network config path to be mounted at /host/etc/cni/net.d.
# - Expects the desired CNI config in the CNI_NETWORK_CONFIG env variable.

# Ensure all variables are defined.
set -u

# Clean up any existing binaries. 
rm -f /host/opt/cni/bin/calico /host/opt/cni/bin/calico-ipam

# Place the new binaries.
cp /opt/cni/bin/calico /host/opt/cni/bin/calico
cp /opt/cni/bin/calico-ipam /host/opt/cni/bin/calico-ipam
echo "Wrote Calico CNI binaries to /host/opt/cni/bin/"
echo "CNI plugin version: $(/host/opt/cni/bin/calico -v)"

# Make the network configuration file.
cat >/host/etc/cni/net.d/10-calico.conf <<EOF
${CNI_NETWORK_CONFIG}
EOF

echo "Wrote CNI config: $(cat /host/etc/cni/net.d/10-calico.conf)"

# Unless told otherwise, sleep forever.
# This prevents Kubernetes from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done configuring CNI.  Sleep=$should_sleep"
while [ "$should_sleep" == "true"  ]; do
	sleep 1;
done
