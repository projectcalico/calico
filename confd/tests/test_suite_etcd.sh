#!/bin/bash

# This script runs a set of tests to verify the Calico client implementation of
# confd.
#
# Data is programmed using calicoctl.

# Make sure confd is not running
pkill -9 confd

# We should exit if any command fails.
set -e

# Add our bins to the PATH
PATH=$PATH:/calico/bin:/calico/bin-node

# Get this script directory, and source the common testsuite (which contains the actual test)
script_dir="$(dirname "$0")"
source "$script_dir/test_suite_common.sh"

# Set the log output directory and ensure the directory exists.
export LOGPATH=/tests/logs/etcd

# We are using etcdv3.  Set the datastore parms for calicoctl/confd/etcdctl
export ETCDCTL_API=3
export DATASTORE_TYPE=etcdv3
export ETCD_ENDPOINTS=http://127.0.0.2:2379
export KUBECONFIG=/home/user/certs/kubeconfig

# Clean etcd of all data
echo "Cleaning out etcd and deleting old logs"
etcdctl del --prefix /calico

# Prepopulate etcd with data that cannot be populated through calicoctl.
echo "Populating etcd with test data that cannot be handled by calicoctl"
while read data; do
    etcdctl put $data > /dev/null 2>&1
done < /tests/mock_data/etcd/block

# Run the tests a few times.
execute_test_suite

echo "Tests completed successfully"

set +e
