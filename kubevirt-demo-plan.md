# KubeVirt Live Migration Demo Plan — KubeCon Europe 2026

## What You Need

**Environment:**
- GCP cluster via Banzai/gkm with nested virtualization (`n2-standard-4` nodes, at least 2 worker nodes)
- Calico installed from `master` branch (with all 4 KubeVirt PRs merged)
- KubeVirt deployed via `gkm run deploy-kubevirt`
- Test VMs created via `gkm run create-vms` / `gkm run setup-vms`

**Tools on your laptop:**
- `gkm` (GCP KubeVirt Manager — SSH, status, BGP route inspection)
- `kubectl`, `calicoctl`
- A terminal multiplexer like `tmux` (to show multiple panes simultaneously)
- A screen recorder (OBS Studio, or `asciinema` for terminal-only)

---

## Environment Setup (before recording)

```bash
export BZ_ROOT_DIR=/path/to/your/banzai/cluster

# 1. Enable nested virtualization on GCP nodes
gkm run enable-nested

# 2. Setup L2TP networking between nodes
gkm run setup-l2tp

# 3. Install Calico via Banzai
pushd "$BZ_ROOT_DIR" && bz install && popd

# 4. Deploy KubeVirt
gkm run deploy-kubevirt

# 5. Create and configure VMs (creates vm1, vm2, ... in default namespace)
gkm run create-vms
gkm run setup-vms

# 6. Verify everything is healthy
gkm run status

# 7. Enable KubeVirt IP persistence
calicoctl ipam configure --kubevirt-ip-persistence=Enabled

# 8. Pre-install nginx inside vm1 (for connectivity test)
gkm connect vm1
# Inside VM:
#   sudo apt-get update && sudo apt-get install -y nginx && sudo systemctl start nginx
#   exit
```

---

## Demo Script (4 segments, ~8-10 minutes total)

### Segment 1: Show Bridge Mode — VM IP = Pod IP (~2 min)

```bash
# Show the running VMs (created in default namespace by gkm)
kubectl get vm -n default
kubectl get vmi -n default

# Show the virt-launcher pod backing vm1
kubectl get pods -n default -l vm=vm1 -o wide

# Capture the Pod IP and the Node it's on
POD_IP=$(kubectl get pod -n default -l vm=vm1 \
  -o jsonpath='{.items[0].status.podIP}')
NODE=$(kubectl get pod -n default -l vm=vm1 \
  -o jsonpath='{.items[0].spec.nodeName}')
echo "Pod IP: $POD_IP  Node: $NODE"

# SSH into vm1 via gkm and show it has the same IP
gkm connect vm1
# Inside VM:
#   ip addr show eth0
#   exit
# Highlight: the VM's eth0 has the SAME IP as the pod — this is bridge mode

# Show the Calico workload endpoint for vm1
calicoctl get workloadendpoint -n default --output wide | grep vm1

# Show BGP routes on the TOR router
gkm tor show-route
```

**Talking point:** "In bridge mode, the VM gets the exact same IP as its backing pod. Calico's IPAM assigns the IP to the pod, and KubeVirt bridges it into the VM."

---

### Segment 2: Show IPAM State Before Migration (~1 min)

```bash
# Show IPAM allocation — the IP is owned by the source pod with a VM-based handle
calicoctl ipam show --ip=$POD_IP

# Key things to highlight:
# - HandleID: k8s-pod-network.vmi.default.vm1 (stable, VM-based, not pod-UID-based)
# - Active Owner: the current virt-launcher pod
# - AlternateOwner: empty (no migration in progress)

# Show IPAM configuration
calicoctl ipam configure show
# Highlight: KubeVirtVMAddressPersistence: Enabled
```

**Talking point:** "Notice the handle ID is `k8s-pod-network.vmi.default.vm1` — based on the VM name, not the pod UID. This stays the same even when the pod changes during migration."

---

### Segment 3: Live Migration with Connection Persistence (~4 min)

Use **tmux with 2-3 panes** side by side.

**Pane 1 (left) — Continuous connectivity test:**

```bash
# Option A: Continuous ping from another pod in default namespace
kubectl run ping-client -n default --image=busybox --rm -it -- \
  sh -c "while true; do ping -c 1 -W 1 $POD_IP && sleep 0.5; done"

# Option B (better visual): Continuous HTTP requests to nginx inside vm1
kubectl run http-client -n default --image=curlimages/curl --rm -it -- \
  sh -c 'while true; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 http://'"$POD_IP"')
    echo "$(date +%H:%M:%S) HTTP $CODE"
    sleep 1
  done'
```

**Pane 2 (right-top) — Watch pods and migration status:**

```bash
# Watch pods in real-time (shows source + target pod appearing)
watch -n1 "kubectl get pods -n default -l vm=vm1 -o wide; \
  echo '---'; \
  kubectl get vmim -n default"
```

**Pane 3 (right-bottom) — Trigger migration and inspect:**

```bash
# Trigger live migration of vm1
cat <<'EOF' | kubectl apply -f -
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstanceMigration
metadata:
  name: demo-migration
  namespace: default
spec:
  vmiName: vm1
EOF

# Watch migration phases: Scheduling → TargetReady → Running → Succeeded
kubectl get vmim -n default -w

# Show BGP routes shifting during migration
gkm tor show-route
# The route for $POD_IP moves from one worker node to another
```

**After migration completes:**

```bash
# Show the pod moved to a different node, same IP
kubectl get pods -n default -l vm=vm1 -o wide

# Confirm new node is different from original
NEW_NODE=$(kubectl get pod -n default -l vm=vm1 \
  -o jsonpath='{.items[0].spec.nodeName}')
echo "Before: $NODE → After: $NEW_NODE"

# Go back to Pane 1 — the ping/HTTP requests never stopped
# Highlight: no dropped packets or failed HTTP requests

# Show routes updated on the TOR
gkm tor show-route
```

**Talking point:** "Watch the left pane — the HTTP requests keep succeeding throughout the migration. On the right, you can see KubeVirt creating a target pod, Calico setting up the alternate owner, and then atomically swapping ownership when migration completes."

---

### Segment 4: Verify Post-Migration State (~1 min)

```bash
# SSH into vm1 via gkm — same IP still there
gkm connect vm1
# Inside VM:
#   ip addr show eth0
#   exit

# Show IPAM state after migration
calicoctl ipam show --ip=$POD_IP
# Highlight: Same HandleID (k8s-pod-network.vmi.default.vm1),
# but Active Owner is now the NEW virt-launcher pod on the new node

# Show the workload endpoint updated
calicoctl get workloadendpoint -n default --output wide | grep vm1

# Show BGP route now points to the new node
gkm tor show-route
```

**Talking point:** "The IP address, the IPAM allocation, and the network policy all carried over seamlessly. From the VM's perspective, nothing changed."

---

## Alternative "Wow Factor" Demo: Long-lived TCP Connection

For a stronger demo showing a single TCP connection survives migration:

```bash
# Inside vm1 (via gkm connect vm1), start a TCP server:
nohup python3 -c '
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999)); s.listen(5)
while True:
    c, a = s.accept()
    start = time.time()
    try:
        while True: c.send(f"alive {time.time()-start:.0f}s\n".encode()); time.sleep(1)
    except: pass
' &

# From a client pod in default namespace, connect and watch the stream survive migration:
kubectl run tcp-client -n default --image=busybox --rm -it -- \
  sh -c "nc $POD_IP 9999"
# Output: alive 1s, alive 2s, ... alive 45s (migration happens)... alive 46s, alive 47s...
```

---

## Tips for a Clean Demo Recording

1. **Pre-stage everything.** Have vm1 running, nginx installed, and client pod ready before recording. Only the migration itself should be live.

2. **Use `tmux` with 2-3 panes:**
   - Left: continuous connectivity test (ping or curl loop)
   - Right-top: `watch` on pods + vmim status
   - Right-bottom: where you type commands

3. **Font size:** Use a large terminal font (18-20pt) for readability in recordings.

4. **Pre-run `calicoctl ipam show --ip=$POD_IP`** before and after — highlight the diff in Active Owner.

5. **Fallback if HTTP is flaky:** A simple `ping` loop is more reliable and still demonstrates connectivity retention. Even 1-2 dropped pings during switchover is acceptable.

6. **`gkm tor show-route`** is a great visual — run it before and after migration to show the BGP route moving between nodes.

7. **Record calico-node logs separately** if needed — live log scrolling can be noisy on camera.

8. **Clean up migration resources** between takes:
   ```bash
   kubectl delete vmim demo-migration -n default
   ```
