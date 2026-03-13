#!/bin/bash
# Provision a GCP KubeVirt cluster for the Live Migration Demo
#
# This script provisions a cluster from scratch:
#   1. Create profile template (gcp-kubevirt.tpl.yaml)
#   2. Initialize profile with bz init (Song's branch)
#   3. Provision GCP VMs with bz provision
#   4. Install Calico and deploy KubeVirt with gkm
#   5. Setup TOR node BGP
#   6. Verify everything is running
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
#  Step 6: Setup TOR node
# ============================================================

phase "Step 6: Setup TOR Node"

info "Running gkm setup-tor..."
gkm run setup-tor || fail "gkm setup-tor failed"
pass "TOR node setup complete"

# Fix BIRD kernel route export (gkm setup-tor sets 'export none' in kernel protocol — bug)
# IMPORTANT: Only change 'export none' in the 'protocol kernel' block, NOT in 'template bgp'.
# Changing the BGP template causes the TOR to advertise routes back to the cluster,
# which triggers martian source floods and kills all nodes.
info "Fixing BIRD kernel route export on TOR node..."
CLUSTER_NAME=$(grep '^CLUSTER_NAME:' "$TASKVARS" | awk '{print $2}')
GOOGLE_ZONE=$(grep '^GOOGLE_ZONE:' "$TASKVARS" | awk '{print $2}')
GOOGLE_PROJECT=$(grep '^GOOGLE_PROJECT:' "$TASKVARS" | awk '{print $2}')
TOR_INSTANCE="${CLUSTER_NAME}nch-ubuntu1"
TOR_PUBLIC_IP=$(gcloud compute instances describe "$TOR_INSTANCE" \
    --project="$GOOGLE_PROJECT" --zone="$GOOGLE_ZONE" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)
EXTERNAL_KEY="$BZ_ROOT_DIR/.local/external_key"
if [ -n "$TOR_PUBLIC_IP" ] && [ -f "$EXTERNAL_KEY" ]; then
    SSH_CMD="ssh -i $EXTERNAL_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@$TOR_PUBLIC_IP"
    $SSH_CMD "sudo docker exec bird sed -i '/protocol kernel/,/}/ s/export none;/export all;/' /etc/bird.conf && sudo docker exec bird birdcl configure" 2>/dev/null
    sleep 5
    ROUTE_COUNT=$($SSH_CMD "ip route | grep -c '192.168'" 2>/dev/null || echo "0")
    if [ "$ROUTE_COUNT" -gt 0 ]; then
        pass "BIRD kernel export fixed — $ROUTE_COUNT pod routes in kernel"
    else
        info "BIRD config updated but no routes yet — BGP may still be converging"
    fi
else
    fail "Could not reach TOR node (IP: $TOR_PUBLIC_IP, key: $EXTERNAL_KEY)"
fi

# ============================================================
#  Step 7: Verify
# ============================================================

phase "Step 7: Verify"

KUBECONFIG_PATH=$(grep '^KUBECONFIG:' "$TASKVARS" | awk '{print $2}')
export KUBECONFIG="$KUBECONFIG_PATH"

info "Checking cluster..."
kubectl get nodes --request-timeout=5s || fail "Cannot connect to cluster"
echo
kubectl get vmi -o wide --request-timeout=5s || fail "Cannot list VMIs"
echo
gkm run status || info "gkm status had warnings"

# ============================================================
#  Done
# ============================================================

phase "Cluster Ready!"

echo "============================================"
echo "  Cluster Details"
echo "============================================"
echo "  BZ_ROOT_DIR: $PROFILE_DIR"
echo "  KUBECONFIG:  $KUBECONFIG_PATH"
echo "============================================"
echo
echo "Next steps:"
echo "  1. export BZ_ROOT_DIR=$PROFILE_DIR"
echo "  2. Run: $SCRIPT_DIR/setup.sh    (validate + create BGPPeer)"
echo "  3. Run: $SCRIPT_DIR/tmux-layout.sh  (launch demo tmux)"
