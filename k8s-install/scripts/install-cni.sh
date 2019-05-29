#!/bin/sh

# Script to install Calico CNI on a Kubernetes host.
# - Expects the host CNI binary path to be mounted at /host/opt/cni/bin.
# - Expects the host CNI network config path to be mounted at /host/etc/cni/net.d.
# - Expects the desired CNI config in the CNI_NETWORK_CONFIG env variable.

# Ensure all variables are defined, and that the script fails when an error is hit.
set -u -e

# Capture the usual signals and exit from the script
trap 'echo "INT received, simply exiting..."; exit 0' INT
trap 'echo "TERM received, simply exiting..."; exit 0' TERM
trap 'echo "HUP received, simply exiting..."; exit 0' HUP

# Helper function for raising errors
# Usage:
# some_command || exit_with_error "some_command_failed: maybe try..."
exit_with_error(){
  echo "$1"
  exit 1
}

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
# First check if the dir exists and has anything in it.
if [ "$(ls "${SECRETS_MOUNT_DIR}" 3>/dev/null)" ];
then
  echo "Installing any TLS assets from ${SECRETS_MOUNT_DIR}"
  mkdir -p /host/etc/cni/net.d/calico-tls
  cp -p "${SECRETS_MOUNT_DIR}"/* /host/etc/cni/net.d/calico-tls/
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

# Choose which default cni binaries should be copied
SKIP_CNI_BINARIES=${SKIP_CNI_BINARIES:-""}
SKIP_CNI_BINARIES=",$SKIP_CNI_BINARIES,"
UPDATE_CNI_BINARIES=${UPDATE_CNI_BINARIES:-"true"}

# Place the new binaries if the directory is writeable.
for dir in /host/opt/cni/bin /host/secondary-bin-dir
do
  if [ ! -w "$dir" ];
  then
    echo "$dir is non-writeable, skipping"
    continue
  fi
  for path in /opt/cni/bin/*;
  do
    filename="$(basename "$path")"
    tmp=",$filename,"
    if [ "${SKIP_CNI_BINARIES#*$tmp}" != "$SKIP_CNI_BINARIES" ];
    then
      echo "$filename is in SKIP_CNI_BINARIES, skipping"
      continue
    fi
    if [ "${UPDATE_CNI_BINARIES}" != "true" ] && [ -f $dir/"$filename" ];
    then
      echo "$dir/$filename is already here and UPDATE_CNI_BINARIES isn't true, skipping"
      continue
    fi
    cp "$path" $dir/ || exit_with_error "Failed to copy $path to $dir. This may be caused by selinux configuration on the host, or something else."
  done

  echo "Wrote Calico CNI binaries to $dir"
  echo "CNI plugin version: $($dir/calico -v)"
done

TMP_CONF='/calico.conf.tmp'
# If specified, overwrite the network configuration file.
: "${CNI_NETWORK_CONFIG_FILE:=}"
: "${CNI_NETWORK_CONFIG:=}"
if [ -e "${CNI_NETWORK_CONFIG_FILE}" ]; then
  echo "Using CNI config template from ${CNI_NETWORK_CONFIG_FILE}."
  cp "${CNI_NETWORK_CONFIG_FILE}" "${TMP_CONF}"
elif [ "${CNI_NETWORK_CONFIG}" != "" ]; then
  echo "Using CNI config template from CNI_NETWORK_CONFIG environment variable."
  cat >$TMP_CONF <<EOF
${CNI_NETWORK_CONFIG}
EOF
fi

SERVICE_ACCOUNT_PATH=/var/run/secrets/kubernetes.io/serviceaccount
KUBE_CA_FILE=${KUBE_CA_FILE:-$SERVICE_ACCOUNT_PATH/ca.crt}
SKIP_TLS_VERIFY=${SKIP_TLS_VERIFY:-false}
# Pull out service account token.
SERVICEACCOUNT_TOKEN=$(cat $SERVICE_ACCOUNT_PATH/token)
# TLS_CFG needs to be set regardless (to avoid error when creating calico-kubeconfig)
TLS_CFG=""

# Check if we're running as a k8s pod.
if [ -f "$SERVICE_ACCOUNT_PATH/token" ]; then
  # We're running as a k8d pod - expect some variables.
  if [ -z "${KUBERNETES_SERVICE_HOST}" ]; then
    echo "KUBERNETES_SERVICE_HOST not set"; exit 1;
  fi
  if [ -z "${KUBERNETES_SERVICE_PORT}" ]; then
    echo "KUBERNETES_SERVICE_PORT not set"; exit 1;
  fi

  if [ "$SKIP_TLS_VERIFY" = "true" ]; then
    TLS_CFG="insecure-skip-tls-verify: true"
  elif [ -f "$KUBE_CA_FILE" ]; then
    TLS_CFG="certificate-authority-data: $(base64 -w 0 "$KUBE_CA_FILE")"
  fi

  # Write a kubeconfig file for the CNI plugin.  Do this
  # to skip TLS verification for now.  We should eventually support
  # writing more complete kubeconfig files. This is only used
  # if the provided CNI network config references it.
  touch /host/etc/cni/net.d/calico-kubeconfig
  chmod "${KUBECONFIG_MODE:-600}" /host/etc/cni/net.d/calico-kubeconfig
  cat > /host/etc/cni/net.d/calico-kubeconfig <<EOF
# Kubeconfig file for Calico CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: ${KUBERNETES_SERVICE_PROTOCOL:-https}://[${KUBERNETES_SERVICE_HOST}]:${KUBERNETES_SERVICE_PORT}
    $TLS_CFG
users:
- name: calico
  user:
    token: "${SERVICEACCOUNT_TOKEN}"
contexts:
- name: calico-context
  context:
    cluster: local
    user: calico
current-context: calico-context
EOF

fi

# Insert any of the supported "auto" parameters.
grep "__KUBERNETES_SERVICE_HOST__" $TMP_CONF && sed -i s/__KUBERNETES_SERVICE_HOST__/"${KUBERNETES_SERVICE_HOST}"/g $TMP_CONF
grep "__KUBERNETES_SERVICE_PORT__" $TMP_CONF && sed -i s/__KUBERNETES_SERVICE_PORT__/"${KUBERNETES_SERVICE_PORT}"/g $TMP_CONF
sed -i s/__KUBERNETES_NODE_NAME__/"${KUBERNETES_NODE_NAME:-$(hostname)}"/g $TMP_CONF
sed -i s/__KUBECONFIG_FILENAME__/calico-kubeconfig/g $TMP_CONF
sed -i s/__CNI_MTU__/"${CNI_MTU:-1500}"/g $TMP_CONF

# Use alternative command character "~", since these include a "/".
sed -i s~__KUBECONFIG_FILEPATH__~"${HOST_CNI_NET_DIR}"/calico-kubeconfig~g $TMP_CONF
sed -i s~__ETCD_CERT_FILE__~"${CNI_CONF_ETCD_CERT:-}"~g $TMP_CONF
sed -i s~__ETCD_KEY_FILE__~"${CNI_CONF_ETCD_KEY:-}"~g $TMP_CONF
sed -i s~__ETCD_CA_CERT_FILE__~"${CNI_CONF_ETCD_CA:-}"~g $TMP_CONF
sed -i s~__ETCD_ENDPOINTS__~"${ETCD_ENDPOINTS:-}"~g $TMP_CONF
sed -i s~__ETCD_DISCOVERY_SRV__~"${ETCD_DISCOVERY_SRV:-}"~g $TMP_CONF
sed -i s~__LOG_LEVEL__~"${LOG_LEVEL:-warn}"~g $TMP_CONF

CNI_CONF_NAME=${CNI_CONF_NAME:-10-calico.conf}
CNI_OLD_CONF_NAME=${CNI_OLD_CONF_NAME:-10-calico.conf}

# Log the config file before inserting service account token.
# This way auth token is not visible in the logs.
echo "CNI config: $(cat ${TMP_CONF})"

sed -i s/__SERVICEACCOUNT_TOKEN__/"${SERVICEACCOUNT_TOKEN:-}"/g $TMP_CONF

# Delete old CNI config files for upgrades.
if [ "${CNI_CONF_NAME}" != "${CNI_OLD_CONF_NAME}" ]; then
    rm -f "/host/etc/cni/net.d/${CNI_OLD_CONF_NAME}"
fi
# Move the temporary CNI config into place.
mv "$TMP_CONF" /host/etc/cni/net.d/"${CNI_CONF_NAME}" || \
  exit_with_error "Failed to mv files. This may be caused by selinux configuration on the host, or something else."

echo "Created CNI config ${CNI_CONF_NAME}"

# Unless told otherwise, sleep forever.
# This prevents Kubernetes from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done configuring CNI.  Sleep=$should_sleep"
while [ "$should_sleep" = "true"  ]; do
  # Kubernetes Secrets can be updated.  If so, we need to install the updated
  # version to the host. Just check the timestamp on the certificate to see if it
  # has been updated.  A bit hokey, but likely good enough.
  if [ -e "${SECRETS_MOUNT_DIR}"/etcd-cert ];
  then
    stat_output=$(stat -c%y "${SECRETS_MOUNT_DIR}"/etcd-cert 2>/dev/null)
    sleep 10;
    if [ "$stat_output" != "$(stat -c%y "${SECRETS_MOUNT_DIR}"/etcd-cert 2>/dev/null)" ]; then
      echo "Updating installed secrets at: $(date)"
      cp -p "${SECRETS_MOUNT_DIR}"/* /host/etc/cni/net.d/calico-tls/
    fi
  else
    sleep 10
  fi
done
