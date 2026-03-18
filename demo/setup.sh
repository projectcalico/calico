#!/bin/bash
# Pre-recording setup script for KubeVirt Live Migration Demo
#
# Validates the cluster, creates BGPPeer for TOR node, and generates demo artifacts.
#
# Prerequisites:
#   - BZ_ROOT_DIR exported (cluster dir with .local/ and Taskvars.yml)
#   - gkm, kubectl, gcloud, calicoctl on PATH
#   - GCP credentials configured

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
phase() { echo -e "\n${BLUE}========== $1 ==========${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ============================================================
#  PHASE 1: Validate cluster and tools
# ============================================================

validate_cluster() {
    phase "PHASE 1: Validate Cluster"

    # Check BZ_ROOT_DIR
    [ -n "$BZ_ROOT_DIR" ] || fail "BZ_ROOT_DIR is not set. Export it first: export BZ_ROOT_DIR=/path/to/cluster-dir"
    pass "BZ_ROOT_DIR=$BZ_ROOT_DIR"

    # Read Taskvars
    TASKVARS="$BZ_ROOT_DIR/Taskvars.yml"
    [ -f "$TASKVARS" ] || fail "Taskvars.yml not found at $TASKVARS"
    CLUSTER_NAME=$(grep '^CLUSTER_NAME:' "$TASKVARS" | awk '{print $2}')
    GOOGLE_ZONE=$(grep '^GOOGLE_ZONE:' "$TASKVARS" | awk '{print $2}')
    GOOGLE_PROJECT=$(grep '^GOOGLE_PROJECT:' "$TASKVARS" | awk '{print $2}')
    KUBECONFIG_PATH=$(grep '^KUBECONFIG:' "$TASKVARS" | awk '{print $2}')
    MASTER_NODES=$(grep '^CLUSTER_MASTER_NODES:' "$TASKVARS" | awk '{print $2}')
    WORKER_NODES=$(grep '^CLUSTER_NODES:' "$TASKVARS" | awk '{print $2}')

    export KUBECONFIG="$KUBECONFIG_PATH"

    # Check tools
    info "Checking required tools..."
    which kubectl >/dev/null 2>&1 || fail "kubectl not found in PATH"
    pass "kubectl is available"
    which gkm >/dev/null 2>&1 || fail "gkm not found in PATH"
    pass "gkm is available"

    # Build and install calicoctl from source
    info "Building calicoctl from source..."
    CALICOCTL_BIN="${REPO_ROOT}/calicoctl/bin/calicoctl-linux-amd64"
    if [ -x "$CALICOCTL_BIN" ] && which calicoctl >/dev/null 2>&1; then
        pass "calicoctl already built and available"
    else
        (cd "$REPO_ROOT" && go build -o "$CALICOCTL_BIN" ./calicoctl/calicoctl/) || fail "Failed to build calicoctl"
        sudo cp "$CALICOCTL_BIN" /usr/local/bin/calicoctl || fail "Failed to install calicoctl to /usr/local/bin"
        pass "calicoctl built and installed to /usr/local/bin/calicoctl"
    fi
    which calicoctl >/dev/null 2>&1 || fail "calicoctl not found in PATH after build"
    pass "calicoctl is available"
    echo

    # Check cluster connectivity
    info "Checking cluster connectivity..."
    kubectl get nodes >/dev/null 2>&1 || fail "Cannot connect to cluster. Check KUBECONFIG ($KUBECONFIG_PATH)"
    NODE_COUNT=$(kubectl get nodes --no-headers | wc -l)
    pass "Connected to cluster with $NODE_COUNT nodes"
    echo

    # Check KubeVirt
    info "Checking KubeVirt..."
    KUBEVIRT_PHASE=$(kubectl get kubevirt -n kubevirt kubevirt -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$KUBEVIRT_PHASE" = "Deployed" ] || fail "KubeVirt not deployed (phase: $KUBEVIRT_PHASE)"
    pass "KubeVirt is deployed"
    echo

    # Check VMs
    info "Checking VMs..."
    VM1_STATUS=$(kubectl get vmi vm1 -o jsonpath='{.status.phase}' 2>/dev/null)
    VM2_STATUS=$(kubectl get vmi vm2 -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$VM1_STATUS" = "Running" ] || fail "vm1 is not running (status: $VM1_STATUS)"
    [ "$VM2_STATUS" = "Running" ] || fail "vm2 is not running (status: $VM2_STATUS)"
    pass "vm1 is running"
    pass "vm2 is running"

    VM1_IP=$(kubectl get vmi vm1 -o jsonpath='{.status.interfaces[0].ipAddress}')
    VM2_IP=$(kubectl get vmi vm2 -o jsonpath='{.status.interfaces[0].ipAddress}')
    VM1_NODE=$(kubectl get vmi vm1 -o jsonpath='{.status.nodeName}')
    VM2_NODE=$(kubectl get vmi vm2 -o jsonpath='{.status.nodeName}')
    VM1_POD=$(kubectl get pods -l kubevirt.io=virt-launcher -l vmi.kubevirt.io/id=vm1 --field-selector status.phase=Running --no-headers -o custom-columns=':metadata.name')
    VM1_POD_IP=$(kubectl get pod "$VM1_POD" -o jsonpath='{.status.podIP}')

    echo
    info "VM1: IP=$VM1_IP  Node=$VM1_NODE  Pod=$VM1_POD"
    info "VM2: IP=$VM2_IP  Node=$VM2_NODE"
    echo

    # Verify bridge mode (VM IP == Pod IP)
    info "Checking bridge mode (VM IP == Pod IP)..."
    if [ "$VM1_IP" = "$VM1_POD_IP" ]; then
        pass "Bridge mode confirmed: VM1 IP ($VM1_IP) == Pod IP ($VM1_POD_IP)"
    else
        fail "Bridge mode mismatch: VM1 IP ($VM1_IP) != Pod IP ($VM1_POD_IP)"
    fi
    echo

    # Check IPAM persistence
    info "Checking IPAM persistence configuration..."
    PERSISTENCE=$(kubectl get ipamconfig default -o jsonpath='{.spec.kubeVirtVMAddressPersistence}' 2>/dev/null)
    [ "$PERSISTENCE" = "Enabled" ] || fail "KubeVirt VM address persistence is not enabled (value: $PERSISTENCE)"
    pass "KubeVirt VM address persistence is Enabled"
    echo

    # Check IPAM state
    info "Checking IPAM allocation for vm1..."
    HANDLE=$(calicoctl ipam show --ip="$VM1_IP" --allow-version-mismatch 2>/dev/null | grep "Handle ID:" | awk '{print $3}')
    if echo "$HANDLE" | grep -q "vmi.default.vm1"; then
        pass "VM-based handle ID: $HANDLE"
    else
        fail "Unexpected handle ID: $HANDLE"
    fi
    echo

    # Check cross-VM connectivity
    info "Testing cross-VM connectivity (ping vm1 from a test pod)..."
    kubectl run --rm -i --restart=Never --image=busybox demo-ping-test -- ping -c 3 -W 2 "$VM1_IP" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        pass "Cross-VM connectivity works"
    else
        fail "Cannot ping vm1 ($VM1_IP) from cluster"
    fi
    echo

    # Check no leftover migration objects
    info "Checking for leftover migration objects..."
    VMIM_COUNT=$(kubectl get vmim --no-headers 2>/dev/null | wc -l)
    if [ "$VMIM_COUNT" -gt 0 ]; then
        info "Found $VMIM_COUNT existing migration object(s). Cleaning up..."
        kubectl delete vmim --all
        pass "Cleaned up migration objects"
    else
        pass "No leftover migration objects"
    fi
    echo

    # Resolve TOR node
    TOR_L2TP_IP="172.16.8.$(( MASTER_NODES + WORKER_NODES + 1 ))"
    TOR_INSTANCE="${CLUSTER_NAME}nch-ubuntu1"
    pass "TOR node: $TOR_INSTANCE (zone: $GOOGLE_ZONE, L2TP: $TOR_L2TP_IP)"
    echo
}

# ============================================================
#  PHASE 2: Create BGPPeer for TOR node
# ============================================================

create_bgp_peer() {
    phase "PHASE 2: BGPPeer & BGPFilter Setup"

    # Create BGPFilter so each Calico node only exports its own local pod
    # routes to the TOR, not routes learned via iBGP from other nodes.
    # Without this filter every node re-advertises every /26 block with
    # 'next hop self', and BIRD on the TOR picks the lowest router-ID
    # (master) as preferred next-hop for ALL routes — creating asymmetric
    # routing that triggers kube-proxy's 'ct state invalid drop' rule.
    info "Ensuring BGPFilter 'export-local-only' exists..."
    calicoctl apply --allow-version-mismatch -f - <<'FILTER_EOF'
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: export-local-only
spec:
  exportV4:
    - action: Reject
      source: RemotePeers
    - action: Accept
FILTER_EOF
    pass "BGPFilter 'export-local-only' applied"

    info "Ensuring BGPPeer 'tor-bgp-peer' exists with filter..."
    calicoctl apply --allow-version-mismatch -f - <<EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: tor-bgp-peer
spec:
  peerIP: $TOR_L2TP_IP
  asNumber: 63000
  filters:
    - export-local-only
EOF
    pass "BGPPeer 'tor-bgp-peer' applied (TOR L2TP IP: $TOR_L2TP_IP, ASN: 63000, filter: export-local-only)"
    echo
}

# ============================================================
#  PHASE 3: Summary
# ============================================================

print_summary() {
    phase "PHASE 3: Summary"

    echo "============================================"
    echo "  Environment Summary for Demo"
    echo "============================================"
    echo "  VM1_IP=$VM1_IP"
    echo "  TOR_INSTANCE=$TOR_INSTANCE"
    echo "  TOR_ZONE=$GOOGLE_ZONE"
    echo "  VM1 Node: $VM1_NODE"
    echo "  VM1 Pod:  $VM1_POD"
    echo "  VM2 IP:   $VM2_IP"
    echo "  VM2 Node: $VM2_NODE"
    echo "  KUBECONFIG: $KUBECONFIG"
    echo "  BZ_ROOT_DIR: $BZ_ROOT_DIR"
    echo "============================================"
    echo
    echo -e "${GREEN}All checks passed! Ready to record.${NC}"
    echo
    echo "Next steps:"
    echo "  1. Run: ./demo/tmux-layout.sh"
    echo "  2. All env vars (\$VM1_IP, \$TOR_INSTANCE, \$TOR_ZONE) will be set in every pane."
    echo "  3. The only manual step: paste the real IP for 'nc' on the TOR node"
    echo "     (copy from the summary above)."
}

# ============================================================
#  Main
# ============================================================

validate_cluster
create_bgp_peer
print_summary
