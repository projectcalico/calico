#!/bin/bash
# Provision a GCP KubeVirt cluster for the Live Migration Demo
#
# This script provisions a cluster from scratch:
#   1. Create profile template (gcp-kubevirt.tpl.yaml)
#   2. Initialize profile with bz init (Song's branch)
#   3. Provision GCP VMs with bz provision
#   4. Install Calico and deploy KubeVirt with gkm
#   5. Verify everything is running
#
# Prerequisites:
#   - bz CLI on PATH
#   - GCP credentials configured
#   - Secrets at ~/.banzai/secrets (or set SECRETS_PATH)
#
# Usage:
#   cd /path/to/working/directory
#   /path/to/demo/provision-cluster.sh

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
SECRETS_PATH="${SECRETS_PATH:-$HOME/.banzai/secrets}"
MACHINE_TYPE="${MACHINE_TYPE:-n2-standard-4}"

# ============================================================
#  Step 1: Check prerequisites
# ============================================================

phase "Step 1: Check Prerequisites"

# Cache sudo credentials upfront and keep them alive in the background
sudo -v
(while true; do sudo -n true; sleep 50; done) &
SUDO_KEEPALIVE_PID=$!
trap "kill $SUDO_KEEPALIVE_PID 2>/dev/null" EXIT

which bz >/dev/null 2>&1 || fail "bz CLI not found in PATH"
pass "bz is available"

[ -d "$SECRETS_PATH" ] || fail "Secrets not found at $SECRETS_PATH"
pass "Secrets found at $SECRETS_PATH"

# ============================================================
#  Step 2: Create profile template
# ============================================================

phase "Step 2: Create Profile Template"

TPL_FILE="$PWD/gcp-kubevirt.tpl.yaml"

if [ -f "$TPL_FILE" ]; then
    info "Profile template already exists: $TPL_FILE"
else
    cat > "$TPL_FILE" <<EOF
metadata:
  name: gcp-kubevirt
  desc: GCP cluster with KubeVirt VMs for live migration demo

config:
  secretsPath: $SECRETS_PATH

variables:
  - name: PROVISIONER
    value: gcp-kubeadm
  - name: PRODUCT
    value: calico
  - name: INSTALLER
    value: operator
  - name: RELEASE_STREAM
    value: master
  - name: USE_HASH_RELEASE
    value: true
  - name: K8S_VERSION
    value: stable
  - name: DATAPLANE
    value: CalicoIptables
  - name: NUM_KUBEVIRT_VMS
    value: 2
  - name: NUM_NON_CLUSTER_HOSTS
    value: 2
  - name: NON_CLUSTER_HOST_IMAGE
    value: ubuntu-2204-lts
  - name: GOOGLE_NODE_MACHINE_TYPE
    value: $MACHINE_TYPE
EOF
    pass "Created profile template: $TPL_FILE (machine type: $MACHINE_TYPE)"
fi

# ============================================================
#  Step 3: Initialize profile with bz init
# ============================================================

phase "Step 3: Initialize Profile"

PROFILE_DIR="$PWD/gcp-kubevirt"

if [ -d "$PROFILE_DIR" ]; then
    info "Profile directory already exists: $PROFILE_DIR — reusing"
else
    info "Running bz init tpl with Song's kubevirt-fix branch..."
    bz init tpl -n gcp-kubevirt --core-branch song-kubevirt-fix "$TPL_FILE"
    pass "Profile initialized"
fi

TASKVARS="$PROFILE_DIR/Taskvars.yml"

# ============================================================
#  Step 4: Provision Cluster (~20 minutes)
# ============================================================

phase "Step 4: Provision Cluster (~20 minutes)"

info "Running bz provision..."
(cd "$PROFILE_DIR" && bz provision) || fail "bz provision failed"
pass "Cluster provisioned"

# ============================================================
#  Step 5: Install Calico and deploy KubeVirt
# ============================================================

phase "Step 5: Install Calico & KubeVirt (~15 minutes)"

export BZ_ROOT_DIR="$PROFILE_DIR"

# Install gkm to PATH if not already there
GKM_BIN="$PROFILE_DIR/addons/kubevirt/scripts/gkm/bin/gkm"
if ! which gkm >/dev/null 2>&1; then
    [ -f "$GKM_BIN" ] || fail "gkm binary not found at $GKM_BIN"
    sudo cp "$GKM_BIN" /usr/local/bin/gkm
    pass "gkm installed to /usr/local/bin"
fi

info "Running gkm tasks..."
gkm run install-calico-parent && \
    gkm run deploy-kubevirt && \
    gkm run create-vms && \
    gkm run setup-vms || fail "gkm tasks failed"
pass "Calico and KubeVirt deployed"

# ============================================================
#  Step 7: Verify
# ============================================================

phase "Step 7: Verify"

KUBECONFIG_PATH=$(grep '^KUBECONFIG:' "$TASKVARS" | awk '{print $2}')
export KUBECONFIG="$KUBECONFIG_PATH"

info "Checking cluster connectivity..."
kubectl get nodes --request-timeout=5s || fail "Cannot connect to cluster"
NODE_COUNT=$(kubectl get nodes --no-headers | wc -l)
pass "Connected to cluster with $NODE_COUNT nodes"
echo

# Build and install calicoctl from source
info "Building calicoctl from source..."
CALICOCTL_BIN="${SCRIPT_DIR}/../calicoctl/bin/calicoctl-linux-amd64"
if [ -x "$CALICOCTL_BIN" ] && which calicoctl >/dev/null 2>&1; then
    pass "calicoctl already built and available"
else
    (cd "$SCRIPT_DIR/.." && go build -o "$CALICOCTL_BIN" ./calicoctl/calicoctl/) || fail "Failed to build calicoctl"
    sudo cp "$CALICOCTL_BIN" /usr/local/bin/calicoctl || fail "Failed to install calicoctl to /usr/local/bin"
    pass "calicoctl built and installed to /usr/local/bin/calicoctl"
fi
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
if kubectl run --rm -i --restart=Never --image=busybox demo-ping-test -- ping -c 3 -W 2 "$VM1_IP" >/dev/null 2>&1; then
    pass "Cross-VM connectivity works"
else
    fail "Cannot ping vm1 ($VM1_IP) from cluster"
fi
echo

# Clean up leftover migration objects
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

# ============================================================
#  Done
# ============================================================

phase "Cluster Ready!"

echo "============================================"
echo "  Environment Summary"
echo "============================================"
echo "  BZ_ROOT_DIR:  $PROFILE_DIR"
echo "  KUBECONFIG:   $KUBECONFIG_PATH"
echo "  VM1: IP=$VM1_IP  Node=$VM1_NODE  Pod=$VM1_POD"
echo "  VM2: IP=$VM2_IP  Node=$VM2_NODE"
echo "============================================"
echo
echo "Next steps:"
echo "  1. export BZ_ROOT_DIR=\$PWD/gcp-kubevirt"
echo "  2. export KUBECONFIG=$KUBECONFIG_PATH"
echo "  3. Run: $SCRIPT_DIR/tmux-layout.sh  (launch demo tmux)"
