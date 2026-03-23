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

set -euo pipefail

echo "==> Removing staged policies..."
kubectl delete stagedglobalnetworkpolicy staged-allow-all staged-compliance-deny-all --ignore-not-found
kubectl delete stagednetworkpolicy -n frontend staged-deny-frontend-egress --ignore-not-found
kubectl delete stagednetworkpolicy -n backend staged-isolate-backend --ignore-not-found
kubectl delete stagednetworkpolicy -n monitoring staged-monitoring-lockdown --ignore-not-found
kubectl delete stagedkubernetesnetworkpolicy -n monitoring staged-k8s-deny-all-monitoring --ignore-not-found

echo "==> Removing enforced policies..."
kubectl delete globalnetworkpolicy restrict-external-access audit-all-ingress deny-monitoring-to-db restrict-udp-non-dns --ignore-not-found

echo "==> Removing tiers..."
kubectl delete tier compliance security platform application --ignore-not-found

echo "==> Removing namespaces (this deletes all workloads, services, and namespaced policies)..."
kubectl delete namespace frontend backend database monitoring --ignore-not-found

echo "==> Teardown complete."
