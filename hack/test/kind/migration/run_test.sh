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

# run_test.sh runs a complete v1-to-v3 CRD migration test on an existing kind cluster.
#
# Prerequisites:
#   - Kind cluster running with v1 CRDs and apiserver:
#       KIND_CALICO_API_GROUP=crd.projectcalico.org/v1 make kind-up
#
# This script covers only what needs a live cluster:
#   - The APIService cutover from the aggregated apiserver to CRD-backed serving
#   - calico-node and typha rolling with CALICO_API_GROUP=projectcalico.org/v3
#   - Surviving a force-kill of kube-controllers mid-migration
#   - Zero connectivity loss across the whole migration
#   - v1 CRD cleanup when the completed DatastoreMigration CR is deleted
#
# Everything at the resource level - which types migrate, stored-name handling,
# namespacing, OwnerReference remapping, progress reporting, conflicts, rollback -
# is covered by the envtest FV in
# kube-controllers/pkg/controllers/migration/controller_fv_test.go and
# controller_v1crd_fv_test.go. Do not re-add those assertions here.
#
# To re-run: destroy the cluster and recreate it, then run this script again:
#   make kind-down
#   KIND_CALICO_API_GROUP=crd.projectcalico.org/v1 make kind-up
#   hack/test/kind/migration/run_test.sh

REPO_ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
KIND_DIR=${REPO_ROOT}/hack/test/kind
KUBECONFIG=${KIND_DIR}/kind-kubeconfig.yaml
kubectl="${KIND_DIR}/kubectl"

export KUBECONFIG

passed=0
failed=0
errors=""

function log() {
  echo ""
  echo "========================================================================"
  echo "  $1"
  echo "========================================================================"
}

function pass() {
  echo "  PASS: $1"
  passed=$((passed + 1))
}

function fail() {
  echo "  FAIL: $1"
  failed=$((failed + 1))
  errors="${errors}\n  - $1"
}

###############################################################################
# Step 0: Preflight checks
###############################################################################
log "Step 0: Preflight checks"

if ! ${kubectl} cluster-info &>/dev/null; then
  echo "ERROR: Cannot connect to kind cluster. Is it running?"
  echo "  Run: KIND_CALICO_API_GROUP=crd.projectcalico.org/v1 make kind-up"
  exit 1
fi
echo "  Kind cluster is reachable"

# Verify v1 CRDs exist.
if ! ${kubectl} get crd felixconfigurations.crd.projectcalico.org &>/dev/null; then
  echo "ERROR: v1 CRDs not found. Cluster must be created with KIND_CALICO_API_GROUP=crd.projectcalico.org/v1"
  exit 1
fi
echo "  v1 CRDs (crd.projectcalico.org) found"

# Verify apiserver is running.
if ! ${kubectl} get apiservice v3.projectcalico.org &>/dev/null; then
  echo "ERROR: APIService v3.projectcalico.org not found. Is the apiserver running?"
  exit 1
fi
echo "  APIService v3.projectcalico.org found"

# Grant RBAC for the migration controller to access the DatastoreMigration CRD
# and manage APIServices. This is needed because the migration CRD lives in a
# separate API group (migration.projectcalico.org) that the operator doesn't know about.
${kubectl} apply -f - <<'RBAC'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: calico-migration-controller
rules:
- apiGroups: ["migration.projectcalico.org"]
  resources: ["datastoremigrations", "datastoremigrations/status"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: ["apiregistration.k8s.io"]
  resources: ["apiservices"]
  verbs: ["get", "list", "create", "delete"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["get", "list", "delete"]
- apiGroups: ["crd.projectcalico.org"]
  resources: ["*"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["projectcalico.org"]
  resources: ["*"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: calico-migration-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-migration-controller
subjects:
- kind: ServiceAccount
  name: calico-kube-controllers
  namespace: calico-system
RBAC
echo "  Migration RBAC configured"

# Scale up the operator if it was scaled down (deploy_resources.sh scales it to 0).
# We need kube-controllers running for the migration controller.
echo "  Ensuring kube-controllers is running..."
${kubectl} scale deployment -n calico-system calico-kube-controllers --replicas=1 2>/dev/null || true
${kubectl} wait --for=condition=Available --timeout=120s deployment/calico-kube-controllers -n calico-system

###############################################################################
# Step 1: Deploy connectivity test workloads
###############################################################################
log "Step 1: Deploying connectivity test workloads"

# Pre-load the busybox image into kind nodes so we don't depend on Docker Hub.
echo "  Loading busybox image into kind nodes..."
docker pull busybox:1.36 &>/dev/null || true
${KIND_DIR}/kind load docker-image busybox:1.36 --name kind 2>/dev/null || true

${kubectl} apply -f "${SCRIPT_DIR}/connectivity.yaml"
echo "  Connectivity workloads applied"

echo "  Waiting for server to be ready..."
${kubectl} wait --for=condition=Available --timeout=120s deployment/server -n migration-test

echo "  Waiting for client to be ready..."
${kubectl} wait --for=condition=Available --timeout=120s deployment/client -n migration-test

# Wait for the client to start probing successfully.
echo "  Waiting for connectivity probes to start..."
for i in $(seq 1 30); do
  if ${kubectl} logs -n migration-test -l app=migration-client --tail=5 2>/dev/null | grep -q "PROBE_OK"; then
    echo "  Connectivity probes running"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: Client never got a successful probe"
    ${kubectl} logs -n migration-test -l app=migration-client --tail=20 2>/dev/null
    exit 1
  fi
  sleep 2
done

###############################################################################
# Step 2: Seed test resources via the apiserver
###############################################################################
log "Step 2: Seeding test resources via apiserver"

# HostEndpoint default-denies host traffic. Felix replaces this list, so it repeats
# felix/config/config_params.go's defaults plus the kind registry and kubelet ports.
${kubectl} patch felixconfigurations.projectcalico.org default --type=merge -p '{
  "spec": {
    "failsafeInboundHostPorts": [
      {"protocol": "tcp", "port": 22},
      {"protocol": "udp", "port": 68},
      {"protocol": "tcp", "port": 179},
      {"protocol": "tcp", "port": 2379},
      {"protocol": "tcp", "port": 2380},
      {"protocol": "tcp", "port": 5473},
      {"protocol": "tcp", "port": 6443},
      {"protocol": "tcp", "port": 6666},
      {"protocol": "tcp", "port": 6667},
      {"protocol": "tcp", "port": 5000},
      {"protocol": "tcp", "port": 10250}
    ],
    "failsafeOutboundHostPorts": [
      {"protocol": "udp", "port": 53},
      {"protocol": "udp", "port": 67},
      {"protocol": "tcp", "port": 179},
      {"protocol": "tcp", "port": 2379},
      {"protocol": "tcp", "port": 2380},
      {"protocol": "tcp", "port": 5473},
      {"protocol": "tcp", "port": 6443},
      {"protocol": "tcp", "port": 6666},
      {"protocol": "tcp", "port": 6667},
      {"protocol": "tcp", "port": 5000},
      {"protocol": "tcp", "port": 10250}
    ]
  }
}'
echo "  Failsafe ports extended for the kind registry and kubelet"

# Apply the seed resources. The migration-test namespace was already created by
# connectivity.yaml. These give the migration real data to move while the
# connectivity probe runs; the FV asserts on what lands in v3.
${kubectl} apply -f "${SCRIPT_DIR}/seed-resources.yaml"
echo "  Seed resources applied"

# Give the apiserver a moment to sync.
sleep 3

###############################################################################
# Step 3: Install v3 CRDs alongside v1
###############################################################################
log "Step 3: Installing v3 CRDs (projectcalico.org) alongside v1"

# The v3 CRDs are in api/config/crd/. While the APIService exists, it takes
# precedence for the projectcalico.org group. But the CRDs need to be present
# for when the migration controller deletes the APIService.
${kubectl} apply --server-side --force-conflicts -f "${REPO_ROOT}/api/config/crd/"
echo "  v3 CRDs installed"

###############################################################################
# Step 4: Install migration CRD
###############################################################################
log "Step 4: Installing migration CRD"

# Install the DatastoreMigration CRD (separate from the v3 Calico CRDs — it lives
# in the migration.projectcalico.org group to avoid APIService conflicts).
${kubectl} apply -f "${REPO_ROOT}/kube-controllers/pkg/controllers/migration/crd/"
echo "  DatastoreMigration CRD installed"

if ! ${kubectl} get crd datastoremigrations.migration.projectcalico.org &>/dev/null; then
  echo "ERROR: DatastoreMigration CRD not found after apply"
  exit 1
fi
echo "  DatastoreMigration CRD verified"

###############################################################################
# Step 5: Disruption test — force-kill kube-controllers during migration
###############################################################################
log "Step 5: Disruption test — force-kill kube-controllers during migration"

# Create the migration CR to kick things off.
cat <<'EOF' | ${kubectl} apply -f -
apiVersion: migration.projectcalico.org/v1beta1
kind: DatastoreMigration
metadata:
  name: v1-to-v3
spec:
  type: V1ToV3
EOF
echo "  DatastoreMigration CR 'v1-to-v3' created"

# Wait for migration to enter the Migrating phase, then force-delete the pod.
echo "  Waiting for Migrating phase before killing the pod..."
for i in $(seq 1 60); do
  phase=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  if [ "$phase" = "Migrating" ] || [ "$phase" = "Converged" ] || [ "$phase" = "Complete" ]; then
    echo "  Phase reached: $phase (after ${i}s)"
    break
  fi
  sleep 1
done

# Only force-kill if migration hasn't already completed.
phase=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
if [ "$phase" = "Migrating" ]; then
  echo "  Force-deleting kube-controllers pod..."
  ${kubectl} delete pod -n calico-system -l k8s-app=calico-kube-controllers --force --grace-period=0 2>/dev/null
  echo "  Pod deleted, waiting for replacement..."
  # The replacement schedules and pulls while the datastore is locked, so give it room.
  ${kubectl} wait --for=condition=Available --timeout=300s deployment/calico-kube-controllers -n calico-system
  echo "  kube-controllers restarted"
elif [ "$phase" = "Converged" ] || [ "$phase" = "Complete" ]; then
  echo "  Migration already past Migrating phase ($phase), skipping disruption"
else
  echo "  WARNING: Migration never reached Migrating phase (phase: $phase), skipping disruption"
fi

###############################################################################
# Step 6: Wait for migration to complete
###############################################################################
log "Step 6: Waiting for migration to complete"

TIMEOUT=300
INTERVAL=5
elapsed=0

while [ $elapsed -lt $TIMEOUT ]; do
  phase=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status.phase}' 2>/dev/null || echo "")

  if [ -z "$phase" ]; then
    echo "  [$elapsed/$TIMEOUT] Waiting for status to be set..."
  else
    progress=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status.progress}' 2>/dev/null || echo "")
    echo "  [$elapsed/$TIMEOUT] Phase: $phase  Progress: $progress"
  fi

  case "$phase" in
    Complete)
      echo "  Migration completed successfully!"
      break
      ;;
    Failed)
      echo "  ERROR: Migration failed!"
      echo "  Status:"
      ${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o yaml
      exit 1
      ;;
  esac

  sleep $INTERVAL
  elapsed=$((elapsed + INTERVAL))
done

if [ $elapsed -ge $TIMEOUT ]; then
  echo "  ERROR: Migration timed out after ${TIMEOUT}s"
  echo "  Current status:"
  ${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o yaml 2>/dev/null || echo "  (could not retrieve status)"
  echo ""
  echo "  kube-controllers logs:"
  ${kubectl} logs -n calico-system -l k8s-app=calico-kube-controllers --tail=100 2>/dev/null || true
  exit 1
fi

###############################################################################
# Step 7: Verify the APIService cutover and component reconfiguration
###############################################################################
log "Step 7: Verifying APIService cutover and component reconfiguration"

echo ""
${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o wide
echo ""

# The aggregated APIService should be gone. Kubernetes auto-creates an
# automanaged one in its place once the v3 CRDs are serving the group.
api_svc_label=$(${kubectl} get apiservice v3.projectcalico.org -o jsonpath='{.metadata.labels.kube-aggregator\.kubernetes\.io/automanaged}' 2>/dev/null || echo "")
if [ "$api_svc_label" = "true" ]; then
  pass "APIService v3.projectcalico.org is now CRD-backed (automanaged)"
elif ! ${kubectl} get apiservice v3.projectcalico.org &>/dev/null; then
  pass "APIService v3.projectcalico.org was deleted by migration controller"
else
  fail "APIService v3.projectcalico.org still points to aggregated API server"
fi

# The v3 API group must actually serve reads now that the aggregated apiserver
# is unregistered.
if ${kubectl} get tiers.projectcalico.org &>/dev/null; then
  pass "projectcalico.org/v3 is served by CRDs after cutover"
else
  fail "projectcalico.org/v3 reads failed after cutover"
fi

# calico-node and typha must have been rolled with the v3 API group set. The
# migration only reaches Complete once they have, but assert it directly so a
# regression names the component.
node_api_group=$(${kubectl} get daemonset -n calico-system calico-node \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="calico-node")].env[?(@.name=="CALICO_API_GROUP")].value}' 2>/dev/null || echo "")
if [ "$node_api_group" = "projectcalico.org/v3" ]; then
  pass "calico-node has CALICO_API_GROUP=projectcalico.org/v3"
else
  fail "calico-node CALICO_API_GROUP is '$node_api_group', expected 'projectcalico.org/v3'"
fi

node_updated=$(${kubectl} get daemonset -n calico-system calico-node -o jsonpath='{.status.updatedNumberScheduled}' 2>/dev/null || echo "0")
node_desired=$(${kubectl} get daemonset -n calico-system calico-node -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
if [ "$node_updated" = "$node_desired" ] && [ "$node_desired" != "0" ]; then
  pass "calico-node rollout complete ($node_updated/$node_desired updated)"
else
  fail "calico-node rollout incomplete ($node_updated/$node_desired updated)"
fi

if ${kubectl} get deployment -n calico-system calico-typha &>/dev/null; then
  typha_api_group=$(${kubectl} get deployment -n calico-system calico-typha \
    -o jsonpath='{.spec.template.spec.containers[?(@.name=="calico-typha")].env[?(@.name=="CALICO_API_GROUP")].value}' 2>/dev/null || echo "")
  if [ "$typha_api_group" = "projectcalico.org/v3" ]; then
    pass "calico-typha has CALICO_API_GROUP=projectcalico.org/v3"
  else
    fail "calico-typha CALICO_API_GROUP is '$typha_api_group', expected 'projectcalico.org/v3'"
  fi
else
  echo "  calico-typha not deployed, skipping its API group check"
fi

###############################################################################
# Step 8: Verify continuous connectivity
###############################################################################
log "Step 8: Verifying continuous connectivity during migration"

# Give the client a few more seconds to log post-migration probes.
sleep 5

# Pull the client logs and check for any PROBE_FAIL lines.
client_logs=$(${kubectl} logs -n migration-test -l app=migration-client 2>/dev/null)

total_probes=$(echo "$client_logs" | grep -c "^PROBE_" || true)
ok_probes=$(echo "$client_logs" | grep -c "^PROBE_OK" || true)
fail_probes=$(echo "$client_logs" | grep -c "^PROBE_FAIL" || true)

echo "  Connectivity probe results:"
echo "    Total probes: $total_probes"
echo "    Successful:   $ok_probes"
echo "    Failed:       $fail_probes"

if [ "$fail_probes" -eq 0 ] && [ "$ok_probes" -gt 0 ]; then
  pass "Zero connectivity loss during migration ($ok_probes probes, 0 failures)"
else
  if [ "$ok_probes" -eq 0 ]; then
    fail "No successful probes recorded — connectivity check may not have been running"
  else
    fail "Connectivity loss detected: $fail_probes/$total_probes probes failed"
    echo ""
    echo "  Failed probe timestamps:"
    echo "$client_logs" | grep "^PROBE_FAIL" | head -20
  fi
fi

###############################################################################
# Step 9: Test v1 CRD cleanup via CR deletion (post-completion)
###############################################################################
log "Step 9: Testing v1 CRD cleanup via CR deletion"

# Count v1 CRDs before deletion.
v1_crd_count_before=$(${kubectl} get crd -o name 2>/dev/null | grep "crd.projectcalico.org" | wc -l)
echo "  v1 CRDs before cleanup: $v1_crd_count_before"

if [ "$v1_crd_count_before" -gt 0 ]; then
  # Delete the DatastoreMigration CR. The finalizer should trigger v1 CRD cleanup.
  echo "  Deleting DatastoreMigration CR (triggers v1 CRD cleanup via finalizer)..."
  ${kubectl} delete datastoremigration.migration.projectcalico.org v1-to-v3 --timeout=120s

  # Verify the CR is gone.
  if ${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 &>/dev/null; then
    fail "DatastoreMigration CR still exists after delete"
  else
    pass "DatastoreMigration CR deleted successfully"
  fi

  # Give the CRD deletions a moment to propagate.
  sleep 5

  # Verify v1 CRDs are gone.
  v1_crd_count_after=$(${kubectl} get crd -o name 2>/dev/null | grep "crd.projectcalico.org" | wc -l)
  echo "  v1 CRDs after cleanup: $v1_crd_count_after"
  if [ "$v1_crd_count_after" -eq 0 ]; then
    pass "All v1 CRDs (crd.projectcalico.org) deleted by finalizer"
  else
    fail "v1 CRDs still remain after cleanup (before: $v1_crd_count_before, after: $v1_crd_count_after)"
    ${kubectl} get crd -o name 2>/dev/null | grep "crd.projectcalico.org" || true
  fi
else
  echo "  No v1 CRDs found, skipping cleanup test"
  pass "No v1 CRDs to clean up (already removed)"
fi

###############################################################################
# Summary
###############################################################################
log "Test Summary"

echo ""
echo "  Passed: $passed"
echo "  Failed: $failed"
echo ""

if [ $failed -gt 0 ]; then
  echo "  Failures:"
  echo -e "$errors"
  echo ""
  echo "  --- Debugging info ---"
  echo ""
  echo "  kube-controllers logs (last 50 lines):"
  ${kubectl} logs -n calico-system -l k8s-app=calico-kube-controllers --tail=50 2>/dev/null || true
  echo ""
  exit 1
fi

echo "  All checks passed!"
echo ""
