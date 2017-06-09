#!/bin/sh

# Add our bins to the PATH
PATH=$PATH:/calico/bin

script_dir="$(dirname "$0")"
source "$script_dir/utils.sh"

# This is needed for use in the keys for our templates, both the sed commands
# in utils.sh use them as well as the templates confd uses.
export NODENAME="kube-master"

until kubectl version; do
  echo "Waiting for API server to come online"
  sleep 1
done

echo "Creating TPRs and dummy Nodes"
# This will create the dummy nodes and the third party resources we can populate
kubectl apply -f /tests/tprs.yaml > /dev/null 2>&1
kubectl apply -f /tests/nodes.yaml > /dev/null 2>&1

echo "Waiting for TPRs to apply"
# There is a delay when creating the TPRs and them being ready for use, so we
# try to apply the data until it finally makes it into the API server
until kubectl apply -f /tests/tpr_data.yaml > /dev/null 2>&1; do
  sleep 1
done

get_templates

echo "Running confd against KDD"
confd -kubeconfig=/tests/confd_kubeconfig -onetime -backend=k8s -confdir=/etc/calico/confd -log-level=debug >/dev/null 2>&1 || true
confd -kubeconfig=/tests/confd_kubeconfig -onetime -backend=k8s -confdir=/etc/calico/confd -log-level=debug >/dev/null 2>&1 || true

test_templates
result=$?

exit $result
