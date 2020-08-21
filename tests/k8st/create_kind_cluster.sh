#!/bin/bash -e

# test directory.
TEST_DIR=./tests/k8st

# kubectl binary.
: ${kubectl:=./kubectl}

# kind binary.
: ${KIND:=$TEST_DIR/kind}

# Set config variables needed for ${kubectl}.
export KUBECONFIG=~/.kube/kind-config-kind

function checkModule(){
  MODULE="$1"
  echo "Checking kernel module $MODULE ..."
  if lsmod | grep "$MODULE" &> /dev/null ; then
    return 0
  else
    return 1
  fi
}

function load_image() {
    local node=$1
    docker cp ./calico-node.tar ${node}:/calico-node.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-node.tar
    docker exec -t ${node} rm /calico-node.tar
}

function enable_dual_stack() {
  # Based on instructions in http://docs.projectcalico.org/master/networking/dual-stack.md
  local yaml=$1
  # add assign_ipv4 and assign_ipv6 to CNI config
  sed -i -e '/"type": "calico-ipam"/r /dev/stdin' "${yaml}" <<EOF
              "assign_ipv4": "true",
              "assign_ipv6": "true"
EOF
  sed -i -e 's/"type": "calico-ipam"/"type": "calico-ipam",/' "${yaml}"

  sed -i -e '/"type": "calico"/r /dev/stdin' "${yaml}" <<EOF
     "feature_control": {
         "floating_ips": true
     },
EOF

  # And add all the IPV6 env vars
  sed -i '/# Enable IPIP/r /dev/stdin' "${yaml}" << EOF
            - name: IP6
              value: "autodetect"
            - name: CALICO_IPV6POOL_CIDR
              value: "fd00:10:244::/64"
EOF
  # update FELIX_IPV6SUPPORT=true
  sed -i '/FELIX_IPV6SUPPORT/!b;n;c\              value: "true"' "${yaml}"
}

echo "kubernetes dualstack requires ipvs mode kube-proxy for the moment."
MODULES=("ip_vs" "ip_vs_rr" "ip_vs_wrr" "ip_vs_sh" "nf_conntrack_ipv4")
for m in "${MODULES[@]}"; do
  checkModule $m || {
      echo "Could not find kernel module $m. install it..."
      # Modules could be built into kernel and not exist as a kernel module anymore.
      # For instance, kernel 5.0.0 ubuntu has nf_conntrack_ipv4 built in.
      # So try to install modules required and continue if it failed..
      sudo modprobe $m || true
  }
done
echo

echo "Download kind executable with dual stack support"
# We need to replace kind executable and node image
# with official release once dual stack is fully supported by upstream.
curl -L https://github.com/song-jiang/kind/releases/download/dualstack-1.17.0/kind -o ${KIND}
chmod +x ${KIND}

echo "Create kind cluster"
${KIND} create cluster --image songtjiang/kindnode-dualstack:1.17.0 --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16,fd00:10:244::/64"
  ipFamily: DualStack
nodes:
# the control plane node
- role: control-plane
- role: worker
- role: worker
- role: worker
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta2
  kind: ClusterConfiguration
  metadata:
    name: config
  featureGates:
    IPv6DualStack: true
- |
  apiVersion: kubeproxy.config.k8s.io/v1alpha1
  kind: KubeProxyConfiguration
  metadata:
    name: config
  mode: ipvs
EOF

${kubectl} get no -o wide
${kubectl} get po --all-namespaces -o wide

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 a a 2001:20::8/64 dev eth0
docker exec kind-worker ip -6 a a 2001:20::1/64 dev eth0
docker exec kind-worker2 ip -6 a a 2001:20::2/64 dev eth0
docker exec kind-worker3 ip -6 a a 2001:20::3/64 dev eth0
echo

load_image kind-control-plane
load_image kind-worker
load_image kind-worker2
load_image kind-worker3

echo "Install Calico and Calicoctl for dualstack"
cp $TEST_DIR/infra/calico-kdd.yaml $TEST_DIR/infra/calico.yaml
enable_dual_stack $TEST_DIR/infra/calico.yaml
${kubectl} apply -f $TEST_DIR/infra/calico.yaml
${kubectl} apply -f $TEST_DIR/infra/calicoctl.yaml
echo

echo "Wait Calico to be ready..."
while ! time ${kubectl} wait pod -l k8s-app=calico-node --for=condition=Ready -n kube-system --timeout=300s; do
    # This happens when no matching resources exist yet,
    # i.e. immediately after application of the Calico YAML.
    sleep 5
done
time ${kubectl} wait pod -l k8s-app=calico-kube-controllers --for=condition=Ready -n kube-system --timeout=300s
time ${kubectl} wait pod -l k8s-app=kube-dns --for=condition=Ready -n kube-system --timeout=300s
echo "Calico is running."
echo

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
