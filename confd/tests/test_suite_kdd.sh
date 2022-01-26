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
export LOGPATH=/tests/logs/kdd

# We are using kdd.  Set the datastore parms for calicoctl/confd/etcdctl
export DATASTORE_TYPE=kubernetes
export KUBECONFIG=/home/user/certs/kubeconfig

# CRDs are pulled in from libcalico.
CRDS=../libcalico-go/config/crd

# Prepopulate k8s with data that cannot be populated through calicoctl.
# All tests use the same set of nodes - for k8s these cannot be created through
# calioctl, so we need to create them through kubectl.
echo "Waiting for k8s API server to come on line"
for i in $(seq 1 30); do kubectl apply -f $CRDS 1>/dev/null 2>&1 && break || sleep 1; done

echo "Populating k8s with test data that cannot be handled by calicoctl"
kubectl apply -f $CRDS
kubectl apply -f /tests/mock_data/kdd/nodes.yaml
kubectl apply -f /tests/mock_data/kdd/ipam.yaml

# Use calicoctl to apply some data - this will require the CRDs to be online.  Repeat
# until successful.
echo "Waiting for CRDs to be ready"
for i in $(seq 1 30); do $CALICOCTL apply -f /tests/mock_data/calicoctl/explicit_peering/specific_node/input.yaml 1>/dev/null 2>&1 && break || sleep 1; done
$CALICOCTL apply -f /tests/mock_data/calicoctl/explicit_peering/specific_node/input.yaml
$CALICOCTL delete -f /tests/mock_data/calicoctl/explicit_peering/specific_node/delete.yaml

# Run the tests a few times.
execute_test_suite

echo "Tests completed successfully"

set +e
