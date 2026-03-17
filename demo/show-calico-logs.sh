#!/bin/bash
# Show Calico logs from a live migration
# Usage: ./demo/show-calico-logs.sh [dest-node]
#
# If dest-node is not provided, it auto-detects vm1's current node.
# Run this AFTER migration completes to see what Calico did.

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

header() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

DEST_NODE=${1:-$(kubectl get vmi vm1 -o jsonpath='{.status.nodeName}')}
echo -e "${GREEN}vm1 is on node: ${DEST_NODE}${NC}"

# --- Felix logs on destination node ---
header "Felix logs (destination node: $DEST_NODE)"
echo -e "${YELLOW}These show Felix receiving the new WorkloadEndpoint and programming iptables/routes:${NC}\n"

FELIX_POD=$(kubectl get pods -n calico-system -l k8s-app=calico-node \
  --field-selector spec.nodeName=$DEST_NODE -o jsonpath='{.items[0].metadata.name}')

kubectl logs -n calico-system "$FELIX_POD" -c calico-node --tail=200 | \
  grep -E "WorkloadEndpoint.*virt-launcher-vm1|endpoint_mgr.*virt-launcher-vm1|status_combiner.*virt-launcher-vm1" | \
  tail -15

# --- CNI logs on destination node ---
header "CNI IPAM logs (destination node: $DEST_NODE)"
echo -e "${YELLOW}These show the CNI plugin detecting the migration target and reusing the VM's IP:${NC}\n"

kubectl exec -n calico-system "$FELIX_POD" -c calico-node -- \
  grep -E "virt-launcher-vm1" /var/log/calico/cni/cni.log 2>/dev/null | \
  grep -iE "migrat|handle|owner|reusing|assigned|virt-launcher" | \
  tail -15

# --- Source node logs (if there's a different node) ---
# Find all nodes that have had vm1 pods
ALL_NODES=$(kubectl get pods -A -l vmi.kubevirt.io/id=vm1 -o jsonpath='{.items[*].spec.nodeName}' 2>/dev/null)
for NODE in $ALL_NODES; do
    if [ "$NODE" != "$DEST_NODE" ]; then
        header "CNI IPAM logs (source node: $NODE)"
        echo -e "${YELLOW}These show CNI DEL handling for the source pod:${NC}\n"

        SRC_FELIX=$(kubectl get pods -n calico-system -l k8s-app=calico-node \
          --field-selector spec.nodeName=$NODE -o jsonpath='{.items[0].metadata.name}')

        kubectl exec -n calico-system "$SRC_FELIX" -c calico-node -- \
          grep -E "virt-launcher-vm1" /var/log/calico/cni/cni.log 2>/dev/null | \
          grep -iE "release|del|clear|owner|handle" | \
          tail -10
    fi
done

echo
echo -e "${GREEN}Key things to notice:${NC}"
echo "  1. CNI detected 'isMigrationTarget=true' on the new pod"
echo "  2. The same HandleID (k8s-pod-network.vmi.default.vm1) was reused"
echo "  3. The SAME IP was assigned to the target pod (not a new one)"
echo "  4. Felix programmed the new WorkloadEndpoint with iptables chains and routes"
echo "  5. The source pod's owner attributes were cleared without releasing the IP"
