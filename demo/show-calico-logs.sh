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

FELIX_POD=$(kubectl get pods -n calico-system -l k8s-app=calico-node \
  --field-selector spec.nodeName=$DEST_NODE -o jsonpath='{.items[0].metadata.name}')

# --- Felix logs: live migration FSM and route programming ---
header "Felix live migration logs (destination node: $DEST_NODE)"
echo -e "${YELLOW}Shows GARP detection, FSM transitions, IPAM swap, and route programming:${NC}\n"

kubectl logs -n calico-system "$FELIX_POD" -c calico-node --tail=1000 | \
  grep -E "virt-launcher-vm1" | \
  grep -E "GARP|RARP|Live migration state|Successfully swapped" | \
  sed 's/types.WorkloadEndpointID{[^}]*}/vm1/g' | \
  sed 's/migrationUID="[^"]*"//g' | \
  sed 's/  */ /g' | \
  tail -10

# --- CNI IPAM logs: migration detection and IP reuse ---
header "CNI IPAM logs (destination node: $DEST_NODE)"
echo -e "${YELLOW}Shows migration target detection, VM-based handle ID, and IP reuse:${NC}\n"

kubectl exec -n calico-system "$FELIX_POD" -c calico-node -- \
  grep "virt-launcher-vm1" /var/log/calico/cni/cni.log 2>/dev/null | \
  grep -E "Detected KubeVirt|using IPs|Skipping host-side route" | \
  sed 's/ContainerID="[^"]*"//' | \
  sed 's/Workload="[^"]*"//' | \
  sed 's/WorkloadEndpoint="[^"]*"//' | \
  sed 's/  */ /g' | \
  tail -6

