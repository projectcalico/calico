#!/bin/bash -e

# Clean up background jobs on exit.
set -m
function cleanup() {
  rc=$?
  jobs -p | xargs --no-run-if-empty kill
  exit $rc
}
trap 'cleanup' SIGINT SIGHUP SIGTERM EXIT

function wait_pod_ready() {
  args="$@"

  # Start background process, waiting for the pod to be ready.
  (
    # Wait in a loop because the command fails fast if the pod isn't visible yet.
    while ! ${kubectl} wait pod --for=condition=Ready --timeout=30s $args; do
      echo "Waiting for pod $args to be ready..."
      ${kubectl} get po -o wide $args || true
      sleep 1
    done;
    ${kubectl} wait pod --for=condition=Ready --timeout=300s $args
  ) & pid=$!
  # Start a second background process that implements the actual timeout.
  ( sleep 300; kill $pid ) 2>/dev/null & watchdog=$!
  set +e

  wait $pid 2>/dev/null
  rc=$?
  kill $watchdog 2>/dev/null
  wait $watchdog 2>/dev/null

  if [ $rc -ne 0 ]; then
    echo "Pod $args failed to become ready within 300s"
    echo "collecting diags..."
    ${kubectl} get po -A -o wide
    ${kubectl} describe po $args
    ${kubectl} logs $args
    echo "Pod $args failed to become ready within 300s; diags above ^^"
  fi

  set -e
  return $rc
}

# test directory.
TEST_DIR=./tests/k8st
ARCH=${ARCH:-amd64}
GIT_VERSION=${GIT_VERSION:-`git describe --tags --dirty --always --abbrev=12`}
HELM=../bin/helm
CHART=../bin/tigera-operator-$GIT_VERSION.tgz

# kubectl binary.
: ${kubectl:=../hack/test/kind/kubectl}

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 addr replace 2001:20::8/64 dev eth0
docker exec kind-worker ip -6 addr replace 2001:20::1/64 dev eth0
docker exec kind-worker2 ip -6 addr replace 2001:20::2/64 dev eth0
docker exec kind-worker3 ip -6 addr replace 2001:20::3/64 dev eth0

echo

echo "Load calico/node docker images onto each node"
$TEST_DIR/load_images_on_kind_cluster.sh

echo "Install additional permissions for BGP password"
${kubectl} apply -f $TEST_DIR/infra/additional-rbac.yaml
echo

echo "Install Calico using the helm chart"
$HELM install calico $CHART -f $TEST_DIR/infra/values.yaml -n tigera-operator --create-namespace

echo "Install calicoctl as a pod"
${kubectl} apply -f $TEST_DIR/infra/calicoctl.yaml
echo

echo "Wait for Calico to be ready..."
for app in calico-node calico-kube-controllers calico-apiserver calico-typha whisker goldmane; do
  wait_pod_ready -n calico-system -l k8s-app="$app"
done
wait_pod_ready -l k8s-app=kube-dns -n kube-system
wait_pod_ready calicoctl -n kube-system

echo "Wait for tigera status to be ready"
${kubectl} wait --for=condition=Available tigerastatus/calico
${kubectl} wait --for=condition=Available tigerastatus/apiserver

echo "Calico is running."
echo

echo "Install MetalLB controller for allocating LoadBalancer IPs"
${kubectl} create ns metallb-system || true
${kubectl} apply -f $TEST_DIR/infra/metallb.yaml
${kubectl} apply -f $TEST_DIR/infra/metallb-config.yaml

# Create and monitor a test webserver service for dual stack.
echo "Create test-webserver deployment..."
${kubectl} apply -f tests/k8st/infra/test-webserver.yaml

echo "Wait for client and webserver pods to be ready..."
wait_pod_ready -l pod-name=client
wait_pod_ready -l app=webserver
echo "client and webserver pods are running."
echo

# Show all the pods running for diags purposes.
${kubectl} get po --all-namespaces -o wide
${kubectl} get svc

# Run ipv4 ipv6 connection test
function test_connection() {
  local svc="webserver-ipv$1"
  output=$(${kubectl} exec client -- wget $svc -T 10 -O -)
  echo $output
  if [[ $output != *test-webserver* ]]; then
    echo "connection to $svc service failed"
    exit 1
  fi
}
test_connection 4
test_connection 6

# At the end of it all, scale down the operator so that it doesn't
# make changes to the cluster. Some of our tests modify calico/node, etc.
# We should remove this once we fix up those tests.
${kubectl} scale deployment -n tigera-operator tigera-operator --replicas=0
