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

# Deploy workloads, traffic generators, and Calico policies to produce diverse
# flow logs for testing Whisker filters. Requires a running cluster with Calico installed.
#
# Usage:
#   ./hack/test/whisker/setup-test-traffic.sh
#
# What this creates:
#   - 4 namespaces: frontend, backend, database, monitoring
#   - Workloads: nginx (ports 80, 8080, 9090), busybox TCP listener (5432)
#   - Traffic generators in each namespace (curl + nc + nslookup every 3s)
#   - 4 Calico tiers: compliance, security, platform, application
#   - Enforced policies: GlobalNetworkPolicy, CalicoNetworkPolicy (Allow/Deny/Pass)
#   - Kubernetes NetworkPolicies
#   - Staged policies: StagedGlobalNetworkPolicy, StagedNetworkPolicy, StagedKubernetesNetworkPolicy
#
# Flow log coverage:
#   Namespaces:  frontend, backend, database, monitoring, calico-system, kube-system
#   Ports:       53, 80, 5432, 8080, 9090
#   Protocols:   TCP, UDP
#   Actions:     Allow, Deny, Pass
#   Reporters:   Src, Dst
#   Policy kinds: CalicoNetworkPolicy, GlobalNetworkPolicy, NetworkPolicy, Profile,
#                 StagedGlobalNetworkPolicy, StagedNetworkPolicy, StagedKubernetesNetworkPolicy
#
# Cleanup:
#   ./hack/test/whisker/flows-traffic-generator/teardown-test-traffic.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/manifests"

echo "==> Deploying namespaces and workloads..."
kubectl apply -f "${MANIFESTS_DIR}/01-namespaces-and-workloads.yaml"

echo "==> Deploying traffic generators..."
kubectl apply -f "${MANIFESTS_DIR}/02-traffic-generators.yaml"

echo "==> Creating Calico tiers..."
kubectl apply -f "${MANIFESTS_DIR}/03-tiers.yaml"

echo "==> Applying enforced Calico policies..."
kubectl apply -f "${MANIFESTS_DIR}/04-enforced-policies.yaml"

echo "==> Applying Kubernetes NetworkPolicies..."
kubectl apply -f "${MANIFESTS_DIR}/05-k8s-network-policies.yaml"

echo "==> Applying staged policies..."
kubectl apply -f "${MANIFESTS_DIR}/06-staged-policies.yaml"

echo "==> Waiting for workload pods to be ready..."
for ns in frontend backend database monitoring; do
  kubectl wait --for=condition=Available --timeout=120s -n "${ns}" deployment --all
done

echo "==> Verifying pods:"
for ns in frontend backend database monitoring; do
  echo "--- ${ns} ---"
  kubectl get pods -n "${ns}"
done

echo ""
echo "==> Setup complete. Flow logs should appear in Whisker within ~30 seconds."
echo "    To tear down: ./hack/test/whisker/flows-traffic-generator/teardown-test-traffic.sh"
