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
#       CALICO_API_GROUP=crd.projectcalico.org/v1 make kind-up
#
# What this script does:
#   1. Deploys client/server pods for continuous connectivity probing
#   2. Seeds test resources via the Calico apiserver (stored in v1 CRDs)
#   3. Snapshots v1 resource counts
#   4. Installs v3 CRDs alongside v1
#   5. Installs the DatastoreMigration CRD and creates a migration CR
#   6. Waits for the migration controller to complete
#   7. Verifies migrated resources exist in v3 CRDs
#   8. Verifies zero connectivity loss during migration
#
# To re-run: destroy the cluster and recreate it, then run this script again:
#   make kind-down
#   CALICO_API_GROUP=crd.projectcalico.org/v1 make kind-up
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

function check_resource_exists() {
  local resource="$1"
  local name="$2"
  local namespace="$3"
  local description="$4"

  local ns_flag=""
  if [ -n "$namespace" ]; then
    ns_flag="-n $namespace"
  fi

  if ${kubectl} get "$resource" $ns_flag "$name" &>/dev/null; then
    pass "$description"
  else
    fail "$description"
  fi
}

function check_resource_not_exists() {
  local resource="$1"
  local name="$2"
  local description="$3"

  if ${kubectl} get "$resource" "$name" &>/dev/null; then
    fail "$description"
  else
    pass "$description"
  fi
}

###############################################################################
# Step 0: Preflight checks
###############################################################################
log "Step 0: Preflight checks"

if ! ${kubectl} cluster-info &>/dev/null; then
  echo "ERROR: Cannot connect to kind cluster. Is it running?"
  echo "  Run: CALICO_API_GROUP=crd.projectcalico.org/v1 make kind-up"
  exit 1
fi
echo "  Kind cluster is reachable"

# Verify v1 CRDs exist.
if ! ${kubectl} get crd felixconfigurations.crd.projectcalico.org &>/dev/null; then
  echo "ERROR: v1 CRDs not found. Cluster must be created with CALICO_API_GROUP=crd.projectcalico.org/v1"
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

# Apply the seed resources. The migration-test namespace was already created by connectivity.yaml.
${kubectl} apply -f "${SCRIPT_DIR}/seed-resources.yaml"
echo "  Seed resources applied"

# Give the apiserver a moment to sync.
sleep 3

# Patch OwnerReferences onto some resources to test that they survive migration.
# Two cases:
#   1. OwnerRef to a native K8s resource (Namespace) — UID should be copied as-is.
#   2. OwnerRef to a Calico resource (Tier) — UID will be different on the v3 copy,
#      so the migration controller needs to remap it (or we need to document that it doesn't yet).

NS_UID=$(${kubectl} get namespace migration-test -o jsonpath='{.metadata.uid}')
TIER_UID=$(${kubectl} get tiers.projectcalico.org security -o jsonpath='{.metadata.uid}')
echo "  Namespace migration-test UID: ${NS_UID}"
echo "  Tier security UID: ${TIER_UID}"

# NetworkSet with ownerRef to its Namespace (native K8s owner).
${kubectl} patch networksets.projectcalico.org test-trusted-ips -n migration-test --type=merge -p "{
  \"metadata\": {
    \"ownerReferences\": [{
      \"apiVersion\": \"v1\",
      \"kind\": \"Namespace\",
      \"name\": \"migration-test\",
      \"uid\": \"${NS_UID}\"
    }]
  }
}"
echo "  Patched NetworkSet 'test-trusted-ips' with ownerRef to Namespace"

# GlobalNetworkPolicy with ownerRef to the security Tier (Calico owner).
${kubectl} patch globalnetworkpolicies.projectcalico.org security.test-allow-dns --type=merge -p "{
  \"metadata\": {
    \"ownerReferences\": [{
      \"apiVersion\": \"projectcalico.org/v3\",
      \"kind\": \"Tier\",
      \"name\": \"security\",
      \"uid\": \"${TIER_UID}\"
    }]
  }
}"
echo "  Patched GNP 'security.test-allow-dns' with ownerRef to Tier"

###############################################################################
# Step 3: Snapshot v1 resource state
###############################################################################
log "Step 3: Snapshotting v1 resource state"

echo "  Tiers:"
${kubectl} get tiers.projectcalico.org 2>/dev/null || echo "    (none)"
echo ""
echo "  GlobalNetworkPolicies:"
${kubectl} get globalnetworkpolicies.projectcalico.org 2>/dev/null || echo "    (none)"
echo ""
echo "  NetworkPolicies (migration-test ns):"
${kubectl} get networkpolicies.projectcalico.org -n migration-test 2>/dev/null || echo "    (none)"
echo ""
echo "  HostEndpoints:"
${kubectl} get hostendpoints.projectcalico.org 2>/dev/null || echo "    (none)"
echo ""
echo "  GlobalNetworkSets:"
${kubectl} get globalnetworksets.projectcalico.org 2>/dev/null || echo "    (none)"
echo ""
echo "  NetworkSets (migration-test ns):"
${kubectl} get networksets.projectcalico.org -n migration-test 2>/dev/null || echo "    (none)"
echo ""
echo "  BGPPeers:"
${kubectl} get bgppeers.projectcalico.org 2>/dev/null || echo "    (none)"
echo ""
echo "  IPPools:"
${kubectl} get ippools.projectcalico.org 2>/dev/null || echo "    (none)"

# Also snapshot the raw v1 CRD objects to see the actual stored names.
echo ""
echo "  --- Raw v1 CRD objects (crd.projectcalico.org) ---"
echo "  v1 GlobalNetworkPolicies:"
${kubectl} get globalnetworkpolicies.crd.projectcalico.org --no-headers 2>/dev/null || echo "    (none)"
echo ""
echo "  v1 NetworkPolicies:"
${kubectl} get networkpolicies.crd.projectcalico.org -A --no-headers 2>/dev/null || echo "    (none)"
echo ""
echo "  v1 Tiers:"
${kubectl} get tiers.crd.projectcalico.org --no-headers 2>/dev/null || echo "    (none)"

###############################################################################
# Step 4: Install v3 CRDs alongside v1
###############################################################################
log "Step 4: Installing v3 CRDs (projectcalico.org) alongside v1"

# The v3 CRDs are in api/config/crd/. While the APIService exists, it takes
# precedence for the projectcalico.org group. But the CRDs need to be present
# for when the migration controller deletes the APIService.
${kubectl} apply --server-side --force-conflicts -f "${REPO_ROOT}/api/config/crd/"
echo "  v3 CRDs installed"

###############################################################################
# Step 5: Install migration CRD
###############################################################################
log "Step 5: Installing migration CRD"

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
# Step 6: Disruption test — force-kill kube-controllers during migration
###############################################################################
log "Step 6: Disruption test — force-kill kube-controllers during migration"

# Create the migration CR to kick things off.
cat <<'EOF' | ${kubectl} apply -f -
apiVersion: migration.projectcalico.org/v1
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
  ${kubectl} wait --for=condition=Available --timeout=120s deployment/calico-kube-controllers -n calico-system
  echo "  kube-controllers restarted"
elif [ "$phase" = "Converged" ] || [ "$phase" = "Complete" ]; then
  echo "  Migration already past Migrating phase ($phase), skipping disruption"
else
  echo "  WARNING: Migration never reached Migrating phase (phase: $phase), skipping disruption"
fi

###############################################################################
# Step 7: Wait for migration to complete
###############################################################################
log "Step 7: Waiting for migration to complete"

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

# Verify the finalizer was added during the Pending phase.
finalizers=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.metadata.finalizers}' 2>/dev/null || echo "")
if echo "$finalizers" | grep -q "migration.projectcalico.org/v1-crd-cleanup"; then
  pass "Finalizer present on DatastoreMigration CR"
else
  fail "Finalizer not found on DatastoreMigration CR (got: $finalizers)"
fi

# Verify the saved APIService annotation exists.
saved_apisvc=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.metadata.annotations.migration\.projectcalico\.org/saved-apiservice}' 2>/dev/null || echo "")
if [ -n "$saved_apisvc" ]; then
  pass "Saved APIService annotation present on DatastoreMigration CR"
else
  fail "Saved APIService annotation not found on DatastoreMigration CR"
fi

###############################################################################
# Step 8: Verify migration results
###############################################################################
log "Step 8: Verifying migration results"

echo ""
echo "  --- DatastoreMigration Status ---"
${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3
echo ""
echo "  Wide output (includes priority columns):"
${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o wide
echo ""
${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status}' | python3 -m json.tool 2>/dev/null || \
  ${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status}'
echo ""

# Verify per-type progress was reported.
type_count=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status.progress.typeDetails}' 2>/dev/null | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
completed_types=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status.progress.completedTypes}' 2>/dev/null || echo "0")
total_types=$(${kubectl} get datastoremigration.migration.projectcalico.org v1-to-v3 -o jsonpath='{.status.progress.totalTypes}' 2>/dev/null || echo "0")

if [ "$type_count" -gt 0 ]; then
  pass "Per-type progress reported ($type_count types in typeDetails)"
else
  fail "No per-type progress in typeDetails"
fi

if [ "$completed_types" -gt 0 ] && [ "$completed_types" = "$total_types" ]; then
  pass "All resource types completed (completedTypes=$completed_types, totalTypes=$total_types)"
else
  fail "Type completion mismatch (completedTypes=$completed_types, totalTypes=$total_types)"
fi

echo ""
echo "  --- Checking migrated resources ---"
echo ""

# After the APIService is deleted, projectcalico.org/v3 is now served by the v3 CRDs.
# Verify that the test resources exist.

# Tiers: "default" (auto-created) and "security" (seeded).
check_resource_exists "tiers.projectcalico.org" "default" "" \
  "Tier 'default' exists in v3"
check_resource_exists "tiers.projectcalico.org" "security" "" \
  "Tier 'security' migrated to v3"

# GlobalNetworkPolicies: the "default." prefix should be stripped for default-tier policies.
# "default.test-deny-all" in v1 should become "test-deny-all" in v3.
check_resource_exists "globalnetworkpolicies.projectcalico.org" "test-deny-all" "" \
  "GNP 'test-deny-all' migrated (default. prefix stripped)"

# Non-default tier policy should keep its name.
check_resource_exists "globalnetworkpolicies.projectcalico.org" "security.test-allow-dns" "" \
  "GNP 'security.test-allow-dns' migrated (non-default tier name preserved)"

# NetworkPolicy: "default.test-allow-web" should become "test-allow-web".
check_resource_exists "networkpolicies.projectcalico.org" "test-allow-web" "migration-test" \
  "NP 'test-allow-web' migrated to migration-test namespace (default. prefix stripped)"

# HostEndpoint.
check_resource_exists "hostendpoints.projectcalico.org" "test-hep" "" \
  "HostEndpoint 'test-hep' migrated to v3"

# GlobalNetworkSet.
check_resource_exists "globalnetworksets.projectcalico.org" "test-external-ips" "" \
  "GlobalNetworkSet 'test-external-ips' migrated to v3"

# NetworkSet (namespaced).
check_resource_exists "networksets.projectcalico.org" "test-trusted-ips" "migration-test" \
  "NetworkSet 'test-trusted-ips' migrated to migration-test namespace"

# BGPPeer.
check_resource_exists "bgppeers.projectcalico.org" "test-peer" "" \
  "BGPPeer 'test-peer' migrated to v3"

# IPPool — the default pool created by Calico installation should also be migrated.
# We don't know the exact name, but at least one should exist.
pool_count=$(${kubectl} get ippools.projectcalico.org --no-headers 2>/dev/null | wc -l)
if [ "$pool_count" -gt 0 ]; then
  pass "IPPool(s) migrated to v3 (found $pool_count)"
else
  fail "No IPPools found in v3 CRDs"
fi

# FelixConfiguration — "default" should be migrated.
check_resource_exists "felixconfigurations.projectcalico.org" "default" "" \
  "FelixConfiguration 'default' migrated to v3"

# BGPConfiguration — may or may not exist depending on cluster config.
bgp_count=$(${kubectl} get bgpconfigurations.projectcalico.org --no-headers 2>/dev/null | wc -l)
bgp_v1_count=$(${kubectl} get bgpconfigurations.crd.projectcalico.org --no-headers 2>/dev/null | wc -l)
if [ "$bgp_count" -ge "$bgp_v1_count" ]; then
  pass "BGPConfiguration(s) migrated (v1: $bgp_v1_count, v3: $bgp_count)"
else
  fail "BGPConfiguration count mismatch (v1: $bgp_v1_count, v3: $bgp_count)"
fi

# ClusterInformation — "default" should exist (used for datastore lock/unlock).
check_resource_exists "clusterinformations.projectcalico.org" "default" "" \
  "ClusterInformation 'default' exists in v3"

# Verify the aggregated APIService was replaced by a local (CRD-backed) one.
# K8s auto-creates a local APIService when CRDs exist for a group.
api_svc_label=$(${kubectl} get apiservice v3.projectcalico.org -o jsonpath='{.metadata.labels.kube-aggregator\.kubernetes\.io/automanaged}' 2>/dev/null || echo "")
if [ "$api_svc_label" = "true" ]; then
  pass "APIService v3.projectcalico.org is now CRD-backed (automanaged)"
elif ! ${kubectl} get apiservice v3.projectcalico.org &>/dev/null; then
  pass "APIService v3.projectcalico.org was deleted by migration controller"
else
  fail "APIService v3.projectcalico.org still points to aggregated API server"
fi

# OwnerReference to native K8s resource (Namespace) — UID should be copied as-is.
ns_ownerref_uid=$(${kubectl} get networksets.projectcalico.org test-trusted-ips -n migration-test -o jsonpath='{.metadata.ownerReferences[0].uid}' 2>/dev/null || echo "")
if [ "$ns_ownerref_uid" = "$NS_UID" ]; then
  pass "NetworkSet ownerRef to Namespace preserved (UID: ${ns_ownerref_uid})"
elif [ -n "$ns_ownerref_uid" ]; then
  fail "NetworkSet ownerRef to Namespace has wrong UID (got: ${ns_ownerref_uid}, expected: ${NS_UID})"
else
  fail "NetworkSet ownerRef to Namespace missing after migration"
fi

# OwnerReference to Calico resource (Tier) — the v3 Tier gets a new UID after
# migration. The migration controller should remap the ownerRef UID from the
# old v1 UID to the new v3 UID.
v3_tier_uid=$(${kubectl} get tiers.projectcalico.org security -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
gnp_ownerref_uid=$(${kubectl} get globalnetworkpolicies.projectcalico.org security.test-allow-dns -o jsonpath='{.metadata.ownerReferences[0].uid}' 2>/dev/null || echo "")
if [ "$gnp_ownerref_uid" = "$v3_tier_uid" ]; then
  pass "GNP ownerRef to Tier remapped to v3 UID (UID: ${gnp_ownerref_uid})"
elif [ "$gnp_ownerref_uid" = "$TIER_UID" ]; then
  fail "GNP ownerRef to Tier still has stale v1 UID (${TIER_UID}), expected v3 UID (${v3_tier_uid})"
elif [ -n "$gnp_ownerref_uid" ]; then
  fail "GNP ownerRef to Tier has unexpected UID (got: ${gnp_ownerref_uid}, expected v3: ${v3_tier_uid})"
else
  fail "GNP ownerRef to Tier missing after migration"
fi

# Verify DatastoreReady is true (datastore unlocked).
ds_ready=$(${kubectl} get clusterinformations.projectcalico.org default -o jsonpath='{.spec.datastoreReady}' 2>/dev/null || echo "")
if [ "$ds_ready" = "true" ]; then
  pass "ClusterInformation.spec.datastoreReady is true (datastore unlocked)"
else
  fail "ClusterInformation.spec.datastoreReady is '$ds_ready', expected 'true'"
fi

###############################################################################
# Step 9: Verify continuous connectivity
###############################################################################
log "Step 9: Verifying continuous connectivity during migration"

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
# Step 10: Test v1 CRD cleanup via CR deletion (post-completion)
###############################################################################
log "Step 10: Testing v1 CRD cleanup via CR deletion"

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
