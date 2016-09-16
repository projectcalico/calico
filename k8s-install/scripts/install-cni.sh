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
cat >calico.conf.tmp <<EOF
${CNI_NETWORK_CONFIG}
EOF

# Write a kubeconfig file for the CNI plugin.  Do this
# to skip TLS verification for now.  We should eventually support
# writing more complete kubeconfig files. This is only used 
# if the provided CNI network config references it.
cat > /host/etc/cni/net.d/calico-kubeconfig <<EOF
# Kubeconfig file for Calico CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    insecure-skip-tls-verify: true
users:
- name: calico 
contexts:
- name: calico-context
  context:
    cluster: local
    user: calico 
current-context: calico-context
EOF

# Insert any of the supported "auto" parameters.
SERVICEACCOUNT_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
sed -i s/__KUBERNETES_SERVICE_HOST__/${KUBERNETES_SERVICE_HOST:-}/g calico.conf.tmp
sed -i s/__KUBERNETES_SERVICE_PORT__/${KUBERNETES_SERVICE_PORT:-}/g calico.conf.tmp
sed -i s/__SERVICEACCOUNT_TOKEN__/${SERVICEACCOUNT_TOKEN:-}/g calico.conf.tmp
sed -i s/__KUBECONFIG_FILENAME__/calico-kubeconfig/g calico.conf.tmp

# Use alternative command character "~", since ETCD_ENDPOINTS includes a "/".
sed -i s~__ETCD_ENDPOINTS__~${ETCD_ENDPOINTS:-}~g calico.conf.tmp

# Move the temporary CNI config into place.
mv calico.conf.tmp /host/etc/cni/net.d/${CNI_CONF_NAME:-10-calico.conf}
echo "Wrote CNI config: $(cat /host/etc/cni/net.d/10-calico.conf)"

# Unless told otherwise, sleep forever.
# This prevents Kubernetes from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done configuring CNI.  Sleep=$should_sleep"
while [ "$should_sleep" == "true"  ]; do
	sleep 1;
done
