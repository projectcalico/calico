#!/bin/bash
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

# gateway-setup.sh prepares a kind cluster (already running, with Calico
# installed) for the Gateway API conformance suite:
#   1. Adds an L2 metallb pool whose addresses come from the kind docker
#      bridge subnet, so LB IPs are reachable from the host runner.
#   2. Pre-creates the test-owned `e2e-gateway-conformance` namespace
#      that holds the EnvoyProxy CR.
#   3. Applies the GatewayAPI CR and waits for tigera-operator to install
#      the Gateway API + EnvoyProxy CRDs.
#   4. Applies the EnvoyProxy CR (externalTrafficPolicy=Cluster override).
#   5. Waits for the GatewayClass to reach Accepted=true.
#
# Required environment variables:
#   KUBECONFIG                   - path to the kind kubeconfig
#   GATEWAY_API_CR               - path to gatewayapi.yaml manifest
#   GATEWAY_ENVOY_PROXY          - path to envoyproxy.yaml manifest
#   GATEWAY_METALLB_POOL         - path to metallb-pool.yaml template
#   GATEWAY_CLASS_NAME           - GatewayClass to wait on
#
# Optional:
#   GATEWAY_KIND_DOCKER_NETWORK  - kind docker network name (default: kind)
#   GATEWAY_SETUP_CRD_TIMEOUT    - seconds to wait for CRDs (default: 300)
#   GATEWAY_SETUP_GWC_TIMEOUT    - timeout for GatewayClass condition wait (default: 5m)
#   GATEWAY_ENVOY_PROXY_NS       - EnvoyProxy CR namespace (default: e2e-gateway-conformance)
#   KUBECTL                      - kubectl binary (default: kubectl in PATH, falling
#                                  back to hack/test/kind/kubectl alongside this script)

set -euo pipefail

: "${KUBECONFIG:?KUBECONFIG must be set}"
: "${GATEWAY_API_CR:?GATEWAY_API_CR must be set}"
: "${GATEWAY_ENVOY_PROXY:?GATEWAY_ENVOY_PROXY must be set}"
: "${GATEWAY_METALLB_POOL:?GATEWAY_METALLB_POOL must be set}"
: "${GATEWAY_CLASS_NAME:?GATEWAY_CLASS_NAME must be set}"

GATEWAY_KIND_DOCKER_NETWORK="${GATEWAY_KIND_DOCKER_NETWORK:-kind}"
GATEWAY_SETUP_CRD_TIMEOUT="${GATEWAY_SETUP_CRD_TIMEOUT:-300}"
GATEWAY_SETUP_GWC_TIMEOUT="${GATEWAY_SETUP_GWC_TIMEOUT:-5m}"
GATEWAY_ENVOY_PROXY_NS="${GATEWAY_ENVOY_PROXY_NS:-e2e-gateway-conformance}"

# Pick a kubectl: explicit override > whatever's in PATH > the kubectl
# Calico's kind setup ships next to this script. The kind-shipped one is
# what `make e2e-gateway-setup` ultimately points at on agents that don't
# have kubectl in $PATH (Semaphore, GCP debug VMs).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBECTL="${KUBECTL:-$(command -v kubectl || echo "${SCRIPT_DIR}/kubectl")}"

kctl="${KUBECTL} --kubeconfig=${KUBECONFIG}"

echo "==> Computing L2 metallb pool from kind docker network ${GATEWAY_KIND_DOCKER_NETWORK}"
# Calico's default metallb pool is BGP-mode + public IPs that aren't
# routable from the host. Mirrors envoyproxy/gateway's create-cluster.sh.
subnet_v4=$(docker network inspect "${GATEWAY_KIND_DOCKER_NETWORK}" 2>/dev/null \
  | jq -r '.[].IPAM.Config[]? | select(.Subnet | contains(":") | not) | .Subnet' \
  | head -1)
if [ -z "${subnet_v4}" ]; then
  echo "ERROR: could not determine IPv4 subnet of docker network '${GATEWAY_KIND_DOCKER_NETWORK}'." >&2
  echo "Is the kind cluster up and is jq installed?" >&2
  exit 1
fi
prefix=$(echo "${subnet_v4}" | awk -F. '{print $1"."$2"."$3}')
range="${prefix}.200-${prefix}.250"
echo "    pool addresses ${range} (from subnet ${subnet_v4})"
sed "s|__LB_RANGE_V4__|${range}|g" "${GATEWAY_METALLB_POOL}" | ${kctl} apply -f -

echo "==> Pre-creating ${GATEWAY_ENVOY_PROXY_NS} namespace for the EnvoyProxy CR"
${kctl} create namespace "${GATEWAY_ENVOY_PROXY_NS}" --dry-run=client -o yaml | ${kctl} apply -f -

echo "==> Applying GatewayAPI CR"
${kctl} apply -f "${GATEWAY_API_CR}"

echo "==> Waiting up to ${GATEWAY_SETUP_CRD_TIMEOUT}s for tigera-operator to install Gateway API + EnvoyProxy CRDs"
end=$(( $(date +%s) + GATEWAY_SETUP_CRD_TIMEOUT ))
until ${kctl} get crd gatewayclasses.gateway.networking.k8s.io >/dev/null 2>&1 \
   && ${kctl} get crd envoyproxies.gateway.envoyproxy.io >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "${end}" ]; then
    echo "ERROR: timed out waiting for CRDs" >&2
    ${kctl} get gatewayapi default -o yaml || true
    ${kctl} get tigerastatus || true
    ${kctl} -n tigera-operator logs deploy/tigera-operator --tail=200 || true
    exit 1
  fi
  sleep 5
done

echo "==> Applying EnvoyProxy CR"
${kctl} apply -f "${GATEWAY_ENVOY_PROXY}"

echo "==> Waiting up to ${GATEWAY_SETUP_GWC_TIMEOUT} for GatewayClass ${GATEWAY_CLASS_NAME}"
end=$(( $(date +%s) + 300 ))
until ${kctl} get gatewayclass "${GATEWAY_CLASS_NAME}" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "${end}" ]; then
    echo "ERROR: timed out waiting for gatewayclass/${GATEWAY_CLASS_NAME} to exist" >&2
    ${kctl} get gatewayclass || true
    exit 1
  fi
  sleep 5
done
${kctl} wait --for=condition=Accepted=true --timeout="${GATEWAY_SETUP_GWC_TIMEOUT}" \
  "gatewayclass/${GATEWAY_CLASS_NAME}"

echo "==> Gateway API conformance setup complete"
