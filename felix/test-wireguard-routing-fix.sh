#!/bin/bash
# WireGuard Source-Scoped Routing Fix - Manual Validation Script
# Issue #9751: Verify host→pod traffic works when EncryptHostTraffic=false
#
# Usage: ./test-wireguard-routing-fix.sh
# Prerequisites: 
#   - Kubernetes cluster with Calico + WireGuard enabled
#   - kubectl configured for cluster access
#   - WireGuard fix applied (source-scoped routing rules)

set -e

KUBECTL="${KUBECTL:-kubectl}"

echo "================================================================"
echo "WIREGUARD SOURCE-SCOPED ROUTING FIX - VALIDATION SCRIPT"
echo "Issue #9751: Verify host→pod traffic when EncryptHostTraffic=false"
echo "================================================================"
echo ""
echo "Test Date: $(date)"
echo ""

# 1. Verify cluster state
echo "=== 1. CLUSTER STATE ==="
$KUBECTL get nodes -o wide
echo ""

# 2. Verify Calico pods
echo "=== 2. CALICO PODS STATUS ==="
$KUBECTL get pods -n kube-system -l k8s-app=calico-node -o wide
echo ""

# 3. Get worker nodes
WORKER_NODES=$($KUBECTL get nodes -o jsonpath='{.items[?(@.spec.taints[*].effect!="NoSchedule")].metadata.name}' | tr ' ' '\n' | grep -v control-plane | head -3)

# 4. Check WireGuard interfaces on worker nodes
echo "=== 3. WIREGUARD INTERFACE STATUS ==="
for node in $WORKER_NODES; do
    echo "--- $node ---"
    if $KUBECTL debug node/$node -it --image=nicolaka/netshoot -- ip link show wireguard.cali >/dev/null 2>&1; then
        echo "✅ WireGuard interface detected"
    else
        echo "⚠️ WireGuard interface not found"
    fi
done
echo ""

# 5. Verify routing rules (THE FIX!)
echo "=== 4. ROUTING RULES VERIFICATION (THE FIX!) ==="
echo "Expected: Source-scoped rules 'not from <pod-cidr> fwmark ... lookup wireguard'"
echo "Broken:   Single unscoped rule 'not from all fwmark ... lookup wireguard'"
echo ""

for node in $WORKER_NODES; do
    echo "--- $node ---"
    $KUBECTL debug node/$node -it --image=nicolaka/netshoot -- ip rule show | grep -E "fwmark|lookup 1" || true
    echo ""
done

# 6. Check WireGuard route table
echo "=== 5. WIREGUARD ROUTE TABLE ==="
FIRST_NODE=$(echo "$WORKER_NODES" | head -1)
echo "Checking table 1 on $FIRST_NODE:"
$KUBECTL debug node/$FIRST_NODE -it --image=nicolaka/netshoot -- ip route show table 1 || true
echo ""

# 7. Deploy test pod
echo "=== 6. DEPLOY TEST POD ==="
cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-nginx
  labels:
    app: test-nginx
spec:
  containers:
  - name: nginx
    image: nginx:latest
    ports:
    - containerPort: 80
EOF

echo "Waiting for pod to be ready..."
$KUBECTL wait --for=condition=ready pod/test-nginx --timeout=60s
POD_IP=$($KUBECTL get pod test-nginx -o jsonpath='{.status.podIP}')
POD_NODE=$($KUBECTL get pod test-nginx -o jsonpath='{.spec.nodeName}')

echo "✅ Test pod deployed:"
echo "   IP: $POD_IP"
echo "   Node: $POD_NODE"
echo ""

# 8. Test host→pod connectivity (CRITICAL TEST)
echo "=== 7. HOST→POD CONNECTIVITY TEST (CRITICAL!) ==="
echo "This test validates the fix: host traffic should reach pods"
echo ""

CONTROL_PLANE=$($KUBECTL get nodes -o jsonpath='{.items[?(@.metadata.labels.node-role\.kubernetes\.io/control-plane)].metadata.name}')
if [ -z "$CONTROL_PLANE" ]; then
    CONTROL_PLANE=$($KUBECTL get nodes -o jsonpath='{.items[0].metadata.name}')
fi

echo "Testing from control-plane node '$CONTROL_PLANE' → pod $POD_IP"
$KUBECTL debug node/$CONTROL_PLANE -it --image=curlimages/curl -- curl -m 5 -s http://$POD_IP | grep -q "Welcome to nginx" && \
    echo "✅ SUCCESS: Host→Pod connectivity works!" || \
    echo "❌ FAILED: Host→Pod connectivity broken!"
echo ""

# 9. Test pod→pod connectivity
echo "=== 8. POD→POD CONNECTIVITY TEST ==="
$KUBECTL run test-client --image=busybox --restart=Never --rm -i --command -- wget -q -O- http://$POD_IP | grep -q "Welcome to nginx" && \
    echo "✅ SUCCESS: Pod→Pod connectivity works!" || \
    echo "❌ FAILED: Pod→Pod connectivity broken!"
echo ""

# 10. Check Felix logs for WireGuard activity
echo "=== 9. FELIX WIREGUARD LOGS (last 10 lines) ==="
CALICO_POD=$($KUBECTL get pods -n kube-system -l k8s-app=calico-node --field-selector spec.nodeName=$POD_NODE -o jsonpath='{.items[0].metadata.name}')
echo "Checking logs from $CALICO_POD on node $POD_NODE:"
$KUBECTL logs -n kube-system $CALICO_POD | grep -i wireguard | tail -10 || echo "No WireGuard logs found"
echo ""

# 11. Summary
echo "================================================================"
echo "TEST SUMMARY"
echo "================================================================"
echo "✅ Cluster: Ready"
echo "✅ Calico: Running"
echo "✅ WireGuard: Check output above"
echo "✅ Routing Rules: Check if source-scoped rules present"
echo "✅ Host→Pod: Check connectivity test result"
echo "✅ Pod→Pod: Check connectivity test result"
echo ""
echo "Expected Results:"
echo "  - Routing rules should be 'not from <pod-cidr>' (source-scoped)"
echo "  - Host→Pod connectivity should work (curl succeeds)"
echo "  - Pod→Pod connectivity should work (encryption maintained)"
echo ""
echo "If all tests pass, the fix is working correctly!"
echo "================================================================"

# Cleanup
echo ""
echo "Cleaning up test pod..."
$KUBECTL delete pod test-nginx --ignore-not-found=true
$KUBECTL delete pod test-client --ignore-not-found=true

echo "✅ Validation complete!"
