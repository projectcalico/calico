#!/bin/bash -e

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# run_test.sh installs Calico from manifests/calico.yaml on an existing kind
# cluster and checks that pod networking works. None of the other kind lanes
# install this way: they all go through the operator, which renders its own
# DaemonSet and so cannot catch a manifest that is missing a piece.
#
# The kind node image ships its own copy of the upstream CNI plugins, which
# would hide a manifest that never installs them, so the test deletes them
# before installing and asserts that Calico puts them back.
#
# Prerequisites:
#   - A kind cluster created from hack/test/kind/kind-manifests.config
#   - Calico images pushed to the local kind registry (make kind-build-images)
#
# To re-run:
#   make kind-cluster-destroy KIND_CONFIG=hack/test/kind/kind-manifests.config
#   make kind-manifest-install-test

REPO_ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
KIND_DIR=${REPO_ROOT}/hack/test/kind
KIND_NAME=${KIND_NAME:-kind-manifests}
KUBECONFIG=${KIND_DIR}/${KIND_NAME}-kubeconfig.yaml
kubectl="${KIND_DIR}/kubectl"
kind="${KIND_DIR}/kind"

# Images are pulled from the registry that registry.sh mirrors into the nodes.
IMAGE_REGISTRY=${IMAGE_REGISTRY:-localhost:5000}
IMAGE_PATH=${IMAGE_PATH:-calico}
IMAGE_TAG=${IMAGE_TAG:-test-build}

NAMESPACE=manifest-install-test
WORKLOAD_IMAGE=busybox:1.36
JUNIT_REPORT=${JUNIT_REPORT:-${REPO_ROOT}/report/manifest-install.xml}

# The plugins the CNI config references, plus the two the calico binary installs
# under its own names.
CALICO_PLUGINS="portmap host-local loopback tuning flannel"
REQUIRED_PLUGINS="calico calico-ipam ${CALICO_PLUGINS}"

export KUBECONFIG

passed=0
failed=0
errors=""
results=()
case_start=${SECONDS}
report_written=false
manifest=""

function log() {
  echo ""
  echo "========================================================================"
  echo "  $1"
  echo "========================================================================"
}

function pass() {
  echo "  PASS: $1"
  passed=$((passed + 1))
  record pass "$1" ""
}

# fail takes the check's name and, optionally, what went wrong. The name stays
# the same as the passing case so the published results track one test.
function fail() {
  echo "  FAIL: $1${2:+: $2}"
  failed=$((failed + 1))
  errors="${errors}\n  - $1${2:+: $2}"
  record fail "$1" "${2:-$1}"
}

function record() {
  results+=("$1|$((SECONDS - case_start))|$2|$3")
  case_start=${SECONDS}
}

function escape() {
  echo "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# write_junit reports the checks the way the e2e lanes do, so `test-results
# publish` picks them up.
function write_junit() {
  report_written=true
  mkdir -p "$(dirname "${JUNIT_REPORT}")"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    printf '<testsuite name="Manifest install (KIND)" tests="%d" failures="%d">\n' "$((passed + failed))" "${failed}"
    for result in ${results+"${results[@]}"}; do
      IFS='|' read -r status elapsed name message <<<"${result}"
      printf '  <testcase classname="manifest-install" name="%s" time="%s"' "$(escape "${name}")" "${elapsed}"
      if [ "${status}" = "fail" ]; then
        printf '>\n    <failure message="%s"/>\n  </testcase>\n' "$(escape "${message}")"
      else
        printf '/>\n'
      fi
    done
    echo '</testsuite>'
  } > "${JUNIT_REPORT}"
  echo "  Wrote ${JUNIT_REPORT}"
}

# An unexpected error still leaves a report behind, so the job publishes what
# ran rather than nothing.
function cleanup() {
  rm -f "${manifest}"
  ${report_written} || write_junit
}
trap cleanup EXIT

# summary reports the results and exits, dumping cluster state if anything
# failed. Callers that cannot carry on invoke it early.
function summary() {
  write_junit

  log "Test Summary"

  echo ""
  echo "  Passed: ${passed}"
  echo "  Failed: ${failed}"
  echo ""

  if [ ${failed} -gt 0 ]; then
    echo "  Failures:"
    echo -e "${errors}"
    echo ""
    echo "  --- Debugging info ---"
    ${kubectl} get po -A -o wide 2>&1 || true
    ${kubectl} -n kube-system describe ds calico-node 2>&1 || true
    ${kubectl} -n kube-system logs -l k8s-app=calico-node --all-containers --tail=100 2>&1 || true
    exit 1
  fi

  echo "  All checks passed!"
  echo ""
  exit 0
}

function nodes() {
  ${kind} get nodes --name "${KIND_NAME}"
}

# probe runs an HTTP request from the client pod. Returns non-zero if the
# request fails, so callers can assert on both reachable and blocked.
function probe() {
  ${kubectl} exec -n ${NAMESPACE} deploy/client -- \
    wget -q -T 5 -O /dev/null "$1" 2>/dev/null
}

# probe_blocked inverts probe, for asserting that policy drops the traffic.
function probe_blocked() {
  ! probe "$1"
}

# retry runs a command until it succeeds or the timeout expires.
function retry() {
  local timeout=$1
  shift
  local elapsed=0
  while [ ${elapsed} -lt ${timeout} ]; do
    if "$@"; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  return 1
}

###############################################################################
# Step 0: Preflight checks
###############################################################################
log "Step 0: Preflight checks"

if ! ${kubectl} cluster-info &>/dev/null; then
  echo "ERROR: cannot reach kind cluster ${KIND_NAME}. Is it running?"
  exit 1
fi
echo "  Kind cluster ${KIND_NAME} is reachable"

###############################################################################
# Step 1: Delete the CNI plugins the kind node image ships
###############################################################################
log "Step 1: Deleting the CNI plugins the kind node image ships"

for node in $(nodes); do
  for plugin in ${CALICO_PLUGINS}; do
    docker exec "${node}" rm -f "/opt/cni/bin/${plugin}"
  done
  echo "  ${node}: $(docker exec "${node}" ls /opt/cni/bin | tr '\n' ' ')"
done

###############################################################################
# Step 2: Install Calico from the manifest
###############################################################################
log "Step 2: Installing Calico from manifests/calico.yaml"

manifest=$(mktemp -t calico-manifest-XXXXXX.yaml)

sed -E "s|image: [a-zA-Z0-9./:-]+/([a-z0-9-]+):[A-Za-z0-9_.-]+|image: ${IMAGE_REGISTRY}/${IMAGE_PATH}/\1:${IMAGE_TAG}|g" \
  "${REPO_ROOT}/manifests/calico.yaml" > "${manifest}"
echo "  Images point at ${IMAGE_REGISTRY}/${IMAGE_PATH}:${IMAGE_TAG}:"
grep "image:" "${manifest}" | sort -u | sed 's/^/    /'

# The cluster is created with the Calico CRDs already applied, so the manifest's
# copies land on top of them.
${kubectl} apply --server-side --force-conflicts -f "${manifest}"

echo "  Waiting for calico-node to roll out"
if ${kubectl} -n kube-system rollout status ds/calico-node --timeout=600s; then
  pass "calico-node rolled out"
else
  fail "calico-node rolled out" "the rollout did not finish within 600s"
  summary
fi

echo "  Waiting for nodes to go Ready"
if ${kubectl} wait --for=condition=Ready nodes --all --timeout=300s; then
  pass "Every node went Ready"
else
  fail "Every node went Ready" "a node stayed NotReady for 300s"
  summary
fi

###############################################################################
# Step 3: Check the plugins Calico installed onto each node
###############################################################################
log "Step 3: Checking the CNI plugins on each node"

for node in $(nodes); do
  installed=$(docker exec "${node}" ls /opt/cni/bin)
  missing=""
  for plugin in ${REQUIRED_PLUGINS}; do
    if ! echo "${installed}" | grep -qx "${plugin}"; then
      missing="${missing} ${plugin}"
    fi
  done
  if [ -z "${missing}" ]; then
    pass "${node} has every CNI plugin Calico installs"
  else
    fail "${node} has every CNI plugin Calico installs" "missing:${missing}"
  fi
done

###############################################################################
# Step 4: Deploy the test workloads
###############################################################################
log "Step 4: Deploying the test workloads"

# Pull through the host so the nodes don't each reach Docker Hub.
docker pull ${WORKLOAD_IMAGE} &>/dev/null || true
${kind} load docker-image ${WORKLOAD_IMAGE} --name "${KIND_NAME}"

${kubectl} apply -f "${SCRIPT_DIR}/workloads.yaml"
if ${kubectl} wait --for=condition=Available --timeout=300s -n ${NAMESPACE} deployment/server deployment/client; then
  pass "Both workloads got a pod sandbox and became ready"
else
  ${kubectl} describe pod -n ${NAMESPACE} 2>&1 | tail -40 || true
  fail "Both workloads got a pod sandbox and became ready" "neither deployment became available within 300s"
  summary
fi

server_ip=$(${kubectl} get pod -n ${NAMESPACE} -l app=manifest-install-server -o jsonpath='{.items[0].status.podIP}')
server_node=$(${kubectl} get pod -n ${NAMESPACE} -l app=manifest-install-server -o jsonpath='{.items[0].spec.nodeName}')
client_node=$(${kubectl} get pod -n ${NAMESPACE} -l app=manifest-install-client -o jsonpath='{.items[0].spec.nodeName}')
server_node_ip=$(${kubectl} get node "${server_node}" -o jsonpath='{.status.addresses[0].address}')
echo "  server ${server_ip} on ${server_node}, client on ${client_node}"

###############################################################################
# Step 5: Connectivity
###############################################################################
log "Step 5: Checking connectivity"

if retry 60 probe "http://${server_ip}:8080"; then
  pass "Pod to pod across nodes"
else
  fail "Pod to pod across nodes"
fi

if retry 60 probe "http://server.${NAMESPACE}.svc.cluster.local"; then
  pass "Pod to service by name"
else
  fail "Pod to service by name"
fi

# The hostPort path is the one that needs portmap, which only reaches the node
# if Calico installed it.
if retry 60 probe "http://${server_node_ip}:30080"; then
  pass "Pod to hostPort on the server's node"
else
  fail "Pod to hostPort on the server's node"
fi

###############################################################################
# Step 6: Policy enforcement
###############################################################################
log "Step 6: Checking policy enforcement"

${kubectl} apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: ${NAMESPACE}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

if retry 60 probe_blocked "http://${server_ip}:8080"; then
  pass "Default deny policy blocks pod to pod"
else
  fail "Default deny policy did not block pod to pod"
fi

${kubectl} delete networkpolicy -n ${NAMESPACE} default-deny-ingress

if retry 60 probe "http://${server_ip}:8080"; then
  pass "Connectivity returns once the policy is deleted"
else
  fail "Connectivity did not return once the policy was deleted"
fi

summary
