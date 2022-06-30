#!/bin/bash -e

# test directory.
TEST_DIR=./tests/k8st
ARCH=${ARCH:-amd64}

# kubectl binary.
: ${kubectl:=../hack/test/kind/kubectl}

function checkModule(){
  MODULE="$1"
  echo "Checking kernel module $MODULE ..."
  if lsmod | grep "$MODULE" &> /dev/null ; then
    return 0
  else
    return 1
  fi
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

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 a a 2001:20::8/64 dev eth0
docker exec kind-worker ip -6 a a 2001:20::1/64 dev eth0
docker exec kind-worker2 ip -6 a a 2001:20::2/64 dev eth0
docker exec kind-worker3 ip -6 a a 2001:20::3/64 dev eth0
echo

echo "Load calico/node docker images onto each node"
$TEST_DIR/load_images_on_kind_cluster.sh

echo "Install Calico and Calicoctl for dualstack"
cp $TEST_DIR/infra/calico-kdd.yaml $TEST_DIR/infra/calico.yaml.tmp
sed -i "s/amd64/${ARCH}/" $TEST_DIR/infra/calico.yaml.tmp
enable_dual_stack $TEST_DIR/infra/calico.yaml.tmp
${kubectl} apply -f $TEST_DIR/infra/calico.yaml.tmp
rm $TEST_DIR/infra/calico.yaml.tmp
cp $TEST_DIR/infra/calicoctl.yaml $TEST_DIR/infra/calicoctl.yaml.tmp
sed -i "s/amd64/${ARCH}/" $TEST_DIR/infra/calicoctl.yaml.tmp
${kubectl} apply -f $TEST_DIR/infra/calicoctl.yaml.tmp
rm $TEST_DIR/infra/calicoctl.yaml.tmp
echo

echo "Install additional permissions for BGP password"
${kubectl} apply -f $TEST_DIR/infra/additional-rbac.yaml
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

echo "Deploy Calico apiserver"
cp $TEST_DIR/infra/apiserver.yaml $TEST_DIR/infra/apiserver.yaml.tmp
sed -i "s/amd64/${ARCH}/" $TEST_DIR/infra/apiserver.yaml.tmp
${kubectl} create -f ${TEST_DIR}/infra/apiserver.yaml.tmp
rm $TEST_DIR/infra/apiserver.yaml.tmp
openssl req -x509 -nodes -newkey rsa:4096 -keyout apiserver.key -out apiserver.crt -days 365 -subj "/" -addext "subjectAltName = DNS:calico-api.calico-apiserver.svc"
${kubectl} create secret -n calico-apiserver generic calico-apiserver-certs --from-file=apiserver.key --from-file=apiserver.crt
${kubectl} patch apiservice v3.projectcalico.org -p \
    "{\"spec\": {\"caBundle\": \"$(${kubectl} get secret -n calico-apiserver calico-apiserver-certs -o go-template='{{ index .data "apiserver.crt" }}')\"}}"
time ${kubectl} wait pod -l k8s-app=calico-apiserver --for=condition=Ready -n calico-apiserver --timeout=30s
echo "Calico apiserver is running."

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
