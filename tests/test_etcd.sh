#!/bin/bash

# Add our bins to the PATH
PATH=$PATH:/calico/bin
TO_TEST=$1

script_dir="$(dirname "$0")"
source "$script_dir/utils.sh"
mkdir -p /tests/logs/etcd/${TO_TEST}

# This is needed for use in the keys of our templates, and the sed commands
# in utils.sh use them to create the toml files.
export NODENAME="kube-master"

populate_etcd ${TO_TEST}

get_templates
create_tomls

# Use ETCD_ENDPOINTS in preferences to ETCD_AUTHORITY
ETCD_NODE=http://127.0.0.1:2379

# confd needs a "-node" argument for each etcd endpoint.
ETCD_ENDPOINTS_CONFD=`echo "-node=$ETCD_NODE" | sed -e 's/,/ -node=/g'`

confd -confdir=/etc/calico/confd -onetime -log-level=debug ${ETCD_ENDPOINTS_CONFD} \
        -client-key=${ETCD_KEY_FILE} -client-cert=${ETCD_CERT_FILE} \
        -client-ca-keys=${ETCD_CA_CERT_FILE} >/tests/logs/etcd/${TO_TEST}/log1 2>&1 || true
confd -confdir=/etc/calico/confd -onetime -log-level=debug ${ETCD_ENDPOINTS_CONFD} \
        -client-key=${ETCD_KEY_FILE} -client-cert=${ETCD_CERT_FILE} \
        -client-ca-keys=${ETCD_CA_CERT_FILE} >/tests/logs/etcd/${TO_TEST}/log2 2>&1 || true

test_templates ${TO_TEST}
result=$?

return ${result}
