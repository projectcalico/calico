#!/bin/bash -e

# Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

# deploy_resources.sh installs Calico on a kind cluster via Helm and waits
# for readiness. Images are pulled by kubelet on demand from the local
# kind-registry (populated by `make kind-build-images`); this script does
# not load images.
#
# Required environment variables:
#   REPO_ROOT - absolute path to the repository root
#   KIND      - path to the kind binary
#   KIND_NAME - name of the kind cluster
#
# Optional environment variables:
#   ARCH               - target architecture (default: amd64)
#   GIT_VERSION        - version for chart lookup (default: git describe)
#   CALICO_API_GROUP   - which API group to use
#   VALUES_FILE        - path to base helm values file (default: infra/values.yaml)
#   EXTRA_VALUES_FILES - space-separated list of additional helm values files to
#                        layer on top of VALUES_FILE (later files override earlier)

# Clean up background jobs on exit, and collect diagnostics on failure.
set -m
function cleanup() {
  rc=$?
  if [ $rc -ne 0 ]; then
    collect_diags
  fi
  jobs -p | xargs --no-run-if-empty kill
  exit $rc
}
trap 'cleanup' SIGINT SIGHUP SIGTERM EXIT

: ${REPO_ROOT:?REPO_ROOT must be set}
: ${KIND:?KIND must be set}
: ${KIND_NAME:?KIND_NAME must be set}

# Relative paths in VALUES_FILE / EXTRA_VALUES_FILES are resolved against the
# current working directory, so the script must be invoked from REPO_ROOT.
if [ "$(pwd)" != "${REPO_ROOT}" ]; then
  echo "ERROR: deploy_resources.sh must be run from REPO_ROOT (${REPO_ROOT}), got $(pwd)"
  exit 1
fi

INFRA_DIR=${REPO_ROOT}/hack/test/kind/infra
ARCH=${ARCH:-amd64}
GIT_VERSION=${GIT_VERSION:-$(git -C "${REPO_ROOT}" describe --tags --dirty --always --abbrev=12)}
HELM=${REPO_ROOT}/bin/helm
CHART=${REPO_ROOT}/bin/tigera-operator-${GIT_VERSION}.tgz
VALUES_FILE=${VALUES_FILE:-${INFRA_DIR}/values.yaml}

: ${kubectl:=${REPO_ROOT}/hack/test/kind/kubectl}

# collect_diags prints detailed cluster diagnostics on failure.
# It collects tigerastatus, tigera-operator logs, and logs from failing pods.
function collect_diags() {
  # Guard against kubectl not being set yet (failure during variable init).
  local kctl="${kubectl:-${REPO_ROOT}/hack/test/kind/kubectl}"

  echo ""
  echo "========================================================================"
  echo "  DIAGNOSTICS: Collecting cluster state after failure"
  echo "========================================================================"

  echo ""
  echo "-------- TigeraStatus Resources (YAML) --------"
  ${kctl} get tigerastatus -o yaml 2>&1 || true

  echo ""
  echo "-------- Tigera Operator Logs --------"
  ${kctl} logs -n tigera-operator -l k8s-app=tigera-operator --tail=200 2>&1 || true

  echo ""
  echo "-------- All Pod Status --------"
  ${kctl} get po -A -o wide 2>&1 || true

  echo ""
  echo "-------- Logs from Non-Running / Non-Ready Pods --------"
  ${kctl} get po -A --no-headers 2>/dev/null | while read -r ns name ready status rest; do
    if [ "$status" != "Running" ] && [ "$status" != "Completed" ] && [ "$status" != "Succeeded" ]; then
      echo ""
      echo "---- Pod ${ns}/${name} (Status: ${status}) ----"
      echo "  -- Description --"
      ${kctl} describe pod -n "${ns}" "${name}" 2>&1 || true
      echo "  -- Logs --"
      ${kctl} logs -n "${ns}" "${name}" --all-containers --tail=200 2>&1 || true
      echo "  -- Previous Logs --"
      ${kctl} logs -n "${ns}" "${name}" --all-containers --previous --tail=200 2>&1 || true
    fi
  done

  # Also check for Running pods that aren't fully ready (e.g., 0/1, 1/2).
  ${kctl} get po -A --no-headers 2>/dev/null | while read -r ns name ready status rest; do
    if [ "$status" = "Running" ]; then
      ready_count="${ready%%/*}"
      total_count="${ready##*/}"
      if [ "$ready_count" != "$total_count" ]; then
        echo ""
        echo "---- Pod ${ns}/${name} (Running but not Ready: ${ready}) ----"
        echo "  -- Description --"
        ${kctl} describe pod -n "${ns}" "${name}" 2>&1 || true
        echo "  -- Logs --"
        ${kctl} logs -n "${ns}" "${name}" --all-containers --tail=200 2>&1 || true
        echo "  -- Previous Logs --"
        ${kctl} logs -n "${ns}" "${name}" --all-containers --previous --tail=200 2>&1 || true
      fi
    fi
  done

  echo ""
  echo "========================================================================"
  echo "  END OF DIAGNOSTICS"
  echo "========================================================================"
  echo ""
}

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
  fi

  set -e
  return $rc
}

echo "Set ipv6 address on each node"
docker exec kind-control-plane ip -6 addr replace 2001:20::8/64 dev eth0
docker exec kind-worker ip -6 addr replace 2001:20::1/64 dev eth0
docker exec kind-worker2 ip -6 addr replace 2001:20::2/64 dev eth0
docker exec kind-worker3 ip -6 addr replace 2001:20::3/64 dev eth0

echo

echo "Install additional permissions for BGP password"
${kubectl} apply -f ${INFRA_DIR}/additional-rbac.yaml
echo

# CRDs are already created prior to reaching this script from within lib.Makefile as part
# of kind cluster creation.
echo "Install Calico using the helm chart"

# Build helm -f args: always include the base VALUES_FILE, then any overlays
# in EXTRA_VALUES_FILES. Helm deep-merges the files, with later ones winning.
helm_values_args=(-f "${VALUES_FILE}")
for extra in ${EXTRA_VALUES_FILES:-}; do
  helm_values_args+=(-f "${extra}")
done
echo "Helm values files: ${VALUES_FILE} ${EXTRA_VALUES_FILES:-}"
${HELM} install calico ${CHART} "${helm_values_args[@]}" -n tigera-operator --create-namespace

echo "Install calicoctl as a pod"
${kubectl} apply -f ${INFRA_DIR}/calicoctl.yaml
echo

echo "Install MetalLB controller (L2-only) for Gateway API conformance"
# We ship a stripped metallb v0.14.9 manifest (BGP-mode CRDs and webhooks
# removed). The remaining install provides IPAddressPool + L2Advertisement,
# which Gateway API conformance uses to make LB IPs reachable from the host
# runner via ARP on the kind docker bridge. Calico has no L2 announce path
# of its own today (see confd/pkg/backends/calico/routes.go and the
# loadbalancer controller in kube-controllers).
${kubectl} create ns metallb-system || true
${kubectl} apply -f ${INFRA_DIR}/metallb.yaml
${kubectl} -n metallb-system rollout status deploy/controller --timeout=2m
${kubectl} wait --for=condition=Established --timeout=2m \
  crd/ipaddresspools.metallb.io crd/l2advertisements.metallb.io

# Wait for ALL tigerastatus resources to become Available. This ensures every
# component the operator manages is fully ready before tests begin.
echo "Wait for all TigeraStatus resources to become Available"
for attempt in $(seq 1 120); do
  # Get all tigerastatus resources and check if any are not Available.
  not_ready=$(${kubectl} get tigerastatus -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .status.conditions[?(@.type=="Available")]}{.status}{end}{"\n"}{end}' 2>/dev/null \
    | grep -v "True$" || true)

  if [ -z "$not_ready" ]; then
    # All are Available — but make sure at least the critical ones exist.
    count=$(${kubectl} get tigerastatus --no-headers 2>/dev/null | wc -l)
    if [ "$count" -ge 1 ]; then
      echo "All $count TigeraStatus resources are Available"
      ${kubectl} get tigerastatus 2>&1
      break
    fi
  fi

  if [ "$attempt" -eq 120 ]; then
    echo "FAIL: Timed out waiting for all TigeraStatus to become Available after 600s"
    ${kubectl} get tigerastatus 2>&1 || true
    echo "Not ready:"
    echo "$not_ready"
    exit 1
  fi

  # Every 60s, poke the operator to re-reconcile in case it's in backoff.
  if (( attempt % 12 == 0 )); then
    echo "Still waiting (${attempt}x5s)... poking operator to re-reconcile"
    ${kubectl} get tigerastatus 2>&1 || true
    ${kubectl} annotate installation default --overwrite triggerReconcile=$(date +%s) 2>/dev/null || true
  fi

  sleep 5
done

echo "Wait for Calico to be ready..."
wait_pod_ready -l k8s-app=kube-dns -n kube-system
wait_pod_ready calicoctl -n kube-system
wait_pod_ready -l k8s-app -n calico-system

echo "Calico is running."

# Apply Calico-native LoadBalancer IP pools (80.15.0.0/24 + fdff::/64).
# These replace the legacy metallb default BGP pool; kube-controllers'
# loadbalancer controller now does the IPAM, and confd handles BGP
# advertisement based on each test's BGPConfiguration.
echo "Applying Calico LoadBalancer IP pools"
for attempt in $(seq 1 12); do
  if ${kubectl} apply -f ${INFRA_DIR}/calico-lb-pools.yaml; then
    break
  fi
  echo "calico-lb-pools.yaml apply failed (attempt $attempt/12) — retrying in 5s..."
  sleep 5
done

# Switch Calico's loadbalancer controller to RequestedServicesOnly so it
# only claims Services that explicitly opt in via
# spec.loadBalancerClass=calico or one of the projectcalico.org/* LB
# annotations. The default AllServices mode races metallb's
# ServiceReconciler over unclassified LB Services -- the controllers
# each assign from their own pool and overwrite each other's status.
# Gateway API conformance services are unclassified and need metallb's
# L2 pool, so we want Calico to leave them alone; node k8st BGP tests
# now set loadBalancerClass=calico explicitly (see test_base.py).
for attempt in $(seq 1 12); do
  if ${kubectl} patch kubecontrollersconfiguration default --type=merge \
       --patch '{"spec":{"controllers":{"loadBalancer":{"assignIPs":"RequestedServicesOnly"}}}}'; then
    break
  fi
  echo "kubecontrollersconfiguration patch failed (attempt $attempt/12) — retrying in 5s..."
  sleep 5
done
