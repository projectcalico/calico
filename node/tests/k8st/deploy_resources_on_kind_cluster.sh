#!/bin/bash -e

TEST_DIR=./tests/k8st
HELM=../calico/bin/helm3
GIT_VERSION=${GIT_VERSION:-`git describe --tags --dirty --always --abbrev=12`}
CHART=../calico/bin/tigera-operator-$GIT_VERSION.tgz

# kubectl binary.
: ${kubectl:=../hack/test/kind/kubectl}

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 a a 2001:20::8/64 dev eth0 || true
docker exec kind-worker ip -6 a a 2001:20::1/64 dev eth0 || true
docker exec kind-worker2 ip -6 a a 2001:20::2/64 dev eth0 || true
docker exec kind-worker3 ip -6 a a 2001:20::3/64 dev eth0 || true
echo

echo "Load calico/node docker images onto each node"
$TEST_DIR/load_images_on_kind_cluster.sh

echo "Install Calico using the helm chart"
$HELM install calico $CHART -f $TEST_DIR/infra/values.yaml -n tigera-operator --create-namespace

echo "Install calicoctl as a pod"
${kubectl} apply -f $TEST_DIR/infra/calicoctl.yaml
echo

echo "Wait for Calico to be ready..."
while ! time ${kubectl} wait pod -l k8s-app=calico-node --for=condition=Ready -n calico-system --timeout=300s; do
    # This happens when no matching resources exist yet, i.e., after installing the operator but before it deploys resources.
    sleep 5
done

while ! time ${kubectl} wait pod -l k8s-app=calico-kube-controllers --for=condition=Ready -n calico-system --timeout=300s; do
    # This happens when no matching resources exist yet, i.e., after installing the operator but before it deploys resources.
    sleep 5
done

while ! time ${kubectl} wait pod -l k8s-app=calico-apiserver --for=condition=Ready -n calico-apiserver --timeout=30s; do 
    # This happens when no matching resources exist yet, i.e., after installing the operator but before it deploys resources.
    sleep 5
done

time ${kubectl} wait pod -l k8s-app=kube-dns --for=condition=Ready -n kube-system --timeout=300s
echo "Calico is running."
echo

echo "Install MetalLB controller for allocating LoadBalancer IPs"
${kubectl} create ns metallb-system
${kubectl} apply -f $TEST_DIR/infra/metallb.yaml
${kubectl} apply -f $TEST_DIR/infra/metallb-config.yaml

# Create and monitor a test webserver service for dual stack.
echo "Create test-webserver deployment..."
${kubectl} apply -f tests/k8st/infra/test-webserver.yaml

echo "Wait for client and webserver pods to be ready..."
while ! time ${kubectl} wait pod -l pod-name=client --for=condition=Ready --timeout=300s; do
    sleep 5
done
while ! time ${kubectl} wait pod -l app=webserver --for=condition=Ready --timeout=300s; do
    sleep 5
done
echo "client and webserver pods are running."
echo

# Show all the pods running for diags purposes.
${kubectl} get po --all-namespaces -o wide
${kubectl} get svc

# Run ipv4 ipv6 connection test
function test_connection() {
  local svc="webserver-ipv$1"
  output=$(${kubectl} exec client -- wget $svc -T 5 -O -)
  echo $output
  if [[ $output != *test-webserver* ]]; then
    echo "connection to $svc service failed"
    exit 1
  fi
}
test_connection 4
test_connection 6
