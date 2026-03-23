#!/usr/bin/env bash
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

# Remove all resources created by setup-test-traffic.sh.
#
# Order: all Calico policies (namespaced + global + staged) first, then tiers,
# then namespaces. Deleting Calico resources before the namespace avoids slow
# finalizer-based cleanup that causes namespace deletion to hang.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/manifests"

echo "==> Removing staged policies..."
kubectl delete -f "${MANIFESTS_DIR}/06-staged-policies.yaml" --ignore-not-found --wait=false

echo "==> Removing Kubernetes NetworkPolicies..."
kubectl delete -f "${MANIFESTS_DIR}/05-k8s-network-policies.yaml" --ignore-not-found --wait=false

echo "==> Removing enforced Calico policies..."
kubectl delete -f "${MANIFESTS_DIR}/04-enforced-policies.yaml" --ignore-not-found --wait=false

echo "==> Removing tiers..."
kubectl delete -f "${MANIFESTS_DIR}/03-tiers.yaml" --ignore-not-found --wait=false

echo "==> Force-deleting pods to avoid stuck finalizers..."
for ns in frontend backend database monitoring; do
  kubectl delete pods -n "${ns}" --all --force --grace-period=0 2>/dev/null || true
done

echo "==> Removing namespaces..."
kubectl delete namespace frontend backend database monitoring --ignore-not-found --wait=false

echo "==> Waiting for namespaces to be fully removed..."
for ns in frontend backend database monitoring; do
  if kubectl get namespace "${ns}" &>/dev/null; then
    kubectl wait --for=delete namespace/"${ns}" --timeout=60s 2>/dev/null || \
      echo "    WARNING: namespace ${ns} still terminating after 60s"
  fi
done

echo "==> Teardown complete."
