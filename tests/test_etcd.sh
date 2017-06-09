#!/bin/sh

# Add our bins to the PATH
PATH=$PATH:/calico/bin

script_dir="$(dirname "$0")"
source "$script_dir/utils.sh"

# This is needed for use in the keys of our templates, and the sed commands
# in utils.sh use them to create the toml files.
export NODENAME="kube-master"

echo "Populating etcd with test data"
# The empty data needs to be eval'd with the entire command else we end up with ""
# instead of empty values for these keys.
while read cmd; do
  eval $cmd > /dev/null 2>&1
done < /tests/etcd_empty_data

# We set a bunch of data used to populate the templates.
while read data; do
  etcdctl set $data > /dev/null 2>&1
done < /tests/etcd_data

# Some directories that are required to exist for the templates.
while read dir; do
  etcdctl mkdir $dir > /dev/null 2>&1
done < /tests/etcd_dirs

get_templates

# Use ETCD_ENDPOINTS in preferences to ETCD_AUTHORITY
ETCD_NODE=http://127.0.0.1:2379

# confd needs a "-node" arguments for each etcd endpoint.
ETCD_ENDPOINTS_CONFD=`echo "-node=$ETCD_NODE" | sed -e 's/,/ -node=/g'`

confd -confdir=/etc/calico/confd -onetime ${ETCD_ENDPOINTS_CONFD} \
        -client-key=${ETCD_KEY_FILE} -client-cert=${ETCD_CERT_FILE} \
        -client-ca-keys=${ETCD_CA_CERT_FILE} -keep-stage-file >/dev/null 2>&1 || true
confd -confdir=/etc/calico/confd -onetime ${ETCD_ENDPOINTS_CONFD} \
        -client-key=${ETCD_KEY_FILE} -client-cert=${ETCD_CERT_FILE} \
        -client-ca-keys=${ETCD_CA_CERT_FILE} -keep-stage-file >/dev/null 2>&1 || true

test_templates
result=$?

exit $result
