#!/bin/sh

# Script to install Calico CNI on a Kubernetes host.
# - Expects the host CNI binary path to be mounted at /host/opt/cni/bin.
# - Expects the host CNI network config path to be mounted at /host/etc/cni/net.d.
# - Expects the desired CNI config in the CNI_NETWORK_CONFIG env variable.

# Ensure all variables are defined.
set -u

# The directory on the host where CNI networks are installed. Defaults to
# /etc/cni/net.d, but can be overridden by setting CNI_NET_DIR.  This is used
# for populating absolute paths in the CNI network config to assets
# which are installed in the CNI network config directory.
HOST_CNI_NET_DIR=${CNI_NET_DIR:-/etc/cni/net.d}
HOST_SECRETS_DIR=${HOST_CNI_NET_DIR}/calico-tls

# Directory where we expect that TLS assets will be mounted into
# the calico/cni container.
SECRETS_MOUNT_DIR=${TLS_ASSETS_DIR:-/calico-secrets}

# Clean up any existing binaries / config / assets.
rm -f /host/opt/cni/bin/calico /host/opt/cni/bin/calico-ipam
rm -f /host/etc/cni/net.d/calico-tls/*

# Copy over any TLS assets from the SECRETS_MOUNT_DIR to the host.
if [ -e "${SECRETS_MOUNT_DIR}" ];
then
	echo "Installing any TLS assets from ${SECRETS_MOUNT_DIR}"
	mkdir -p /host/etc/cni/net.d/calico-tls
	cp ${SECRETS_MOUNT_DIR}/* /host/etc/cni/net.d/calico-tls/
fi

# If the TLS assets actually exist, update the variables to populate into the
# CNI network config.  Otherwise, we'll just fill that in with blanks.
if [ -e "/host/etc/cni/net.d/calico-tls/etcd-ca" ];
then
	CNI_CONF_ETCD_CA=${HOST_SECRETS_DIR}/etcd-ca
fi

if [ -e "/host/etc/cni/net.d/calico-tls/etcd-key" ];
then
	CNI_CONF_ETCD_KEY=${HOST_SECRETS_DIR}/etcd-key
fi

if [ -e "/host/etc/cni/net.d/calico-tls/etcd-cert" ];
then
	CNI_CONF_ETCD_CERT=${HOST_SECRETS_DIR}/etcd-cert
fi

# Place the new binaries if the directory is writeable.
if [ -w "/host/opt/cni/bin/" ]; then
	cp /opt/cni/bin/calico /host/opt/cni/bin/
	cp /opt/cni/bin/calico-ipam /host/opt/cni/bin/
	# Copy over the 3rd party CNI binaries, but do not clobber if they exist
	if [ ! -f /host/opt/cni/bin/flannel ]; then
	    cp /opt/cni/bin/flannel /host/opt/cni/bin/
	fi
	if [ ! -f /host/opt/cni/bin/loopback ]; then
	    cp /opt/cni/bin/loopback /host/opt/cni/bin/
	fi
	if [ ! -f /host/opt/cni/bin/host-local ]; then
	    cp /opt/cni/bin/host-local /host/opt/cni/bin/
	fi
	echo "Wrote Calico CNI binaries to /host/opt/cni/bin/"
	echo "CNI plugin version: $(/host/opt/cni/bin/calico -v)"
fi

# Place them in the secondary location if it exists and
# is writeable.
if [ -w "/host/secondary-bin-dir/" ]; then
	cp /opt/cni/bin/calico /host/secondary-bin-dir/
	cp /opt/cni/bin/calico-ipam /host/secondary-bin-dir/
	# Copy over the 3rd party CNI binaries, but do not clobber if they exist
	if [ ! -f /host/secondary-bin-dir/flannel ]; then
	    cp /opt/cni/bin/flannel /host/secondary-bin-dir/
	fi
	if [ ! -f /host/secondary-bin-dir/loopback ]; then
	    cp /opt/cni/bin/loopback /host/secondary-bin-dir/
	fi
	if [ ! -f /host/secondary-bin-dir/host-local ]; then
	    cp /opt/cni/bin/host-local /host/secondary-bin-dir/
	fi
	echo "Wrote Calico CNI binaries to /host/secondary-bin-dir/"
	echo "CNI plugin version: $(/host/secondary-bin-dir/calico -v)"
fi

TMP_CONF='/calico.conf.tmp'
# If specified, overwrite the network configuration file.
if [ "${CNI_NETWORK_CONFIG:-}" != "" ]; then
cat >$TMP_CONF <<EOF
${CNI_NETWORK_CONFIG:-}
EOF
fi

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
sed -i s/__KUBERNETES_SERVICE_HOST__/${KUBERNETES_SERVICE_HOST:-}/g $TMP_CONF
sed -i s/__KUBERNETES_SERVICE_PORT__/${KUBERNETES_SERVICE_PORT:-}/g $TMP_CONF
sed -i s/__KUBERNETES_NODE_NAME__/${KUBERNETES_NODE_NAME:-$(hostname)}/g $TMP_CONF
sed -i s/__SERVICEACCOUNT_TOKEN__/${SERVICEACCOUNT_TOKEN:-}/g $TMP_CONF
sed -i s/__KUBECONFIG_FILENAME__/calico-kubeconfig/g $TMP_CONF

# Use alternative command character "~", since these include a "/".
sed -i s~__KUBECONFIG_FILEPATH__~${HOST_CNI_NET_DIR}/calico-kubeconfig~g $TMP_CONF
sed -i s~__ETCD_CERT_FILE__~${CNI_CONF_ETCD_CERT:-}~g $TMP_CONF
sed -i s~__ETCD_KEY_FILE__~${CNI_CONF_ETCD_KEY:-}~g $TMP_CONF
sed -i s~__ETCD_CA_CERT_FILE__~${CNI_CONF_ETCD_CA:-}~g $TMP_CONF
sed -i s~__ETCD_ENDPOINTS__~${ETCD_ENDPOINTS:-}~g $TMP_CONF

# Move the temporary CNI config into place.
FILENAME=${CNI_CONF_NAME:-10-calico.conf}
mv $TMP_CONF /host/etc/cni/net.d/${FILENAME}
echo "Wrote CNI config: $(cat /host/etc/cni/net.d/${FILENAME})"

# Unless told otherwise, sleep forever.
# This prevents Kubernetes from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done configuring CNI.  Sleep=$should_sleep"
while [ "$should_sleep" == "true"  ]; do
	# Kubernetes Secrets can be updated.  If so, we need to install the updated
	# version to the host. Just check the timestamp on the certificate to see if it
	# has been updated.  A bit hokey, but likely good enough.
	stat_output=$(stat -c%y ${SECRETS_MOUNT_DIR}/etcd-cert 2>/dev/null)
	sleep 10;
	if [ "$stat_output" != "$(stat -c%y ${SECRETS_MOUNT_DIR}/etcd-cert 2>/dev/null)" ]; then
		echo "Updating installed secrets at: $(date)"
		cp ${SECRETS_MOUNT_DIR}/* /host/etc/cni/net.d/calico-tls/
	fi
done
