# KubeVirt Live Migration Demo for KubeCon Europe 2026

## What This Demo Shows

Calico now supports **seamless live migration for KubeVirt VMs**.
When a VM live-migrates from one node to another, Calico ensures:

- The VM keeps the **exact same IP address** on the new node
- **Network connectivity is seamlessly preserved** — existing TCP connections survive
  the migration with no drops or reconnections
- **No manual intervention** is needed — Calico handles IPAM and routing automatically

This is critical for production VM workloads that expect stable IP addresses
and uninterrupted connections (databases, stateful services, long-lived sessions).

---

## Environment Overview

### Cluster Architecture

```
  +-------------------- KUBERNETES CLUSTER ---------------------+
  |                                                             |
  |  +--------------------+                                     |
  |  |   CONTROL PLANE    |                                     |
  |  |   ASN 64512        |                                     |
  |  +--------------------+                                     |
  |                                                             |
  |  +------------+   +------------+    +------------+          |
  |  |  WORKER 0  |   |  WORKER 1  |    |  WORKER 2  |          |
  |  |            |   |            |    |            |          |
  |  |  +------+  |   |  +------+  |    | (MIGRATION |          |
  |  |  | VM1  |  |   |  | VM2  |  |    |  TARGET)   |          |
  |  |  +------+  |   |  +------+  |    |            |          |
  |  +------------+   +------------+    +------------+          |
  |                                                             |
  |  CALICO: iBGP MESH, IPTABLES DATAPLANE                     |
  |  KUBEVIRT: BRIDGE MODE NETWORKING                           |
  +-------------------------------------------------------------+
```

- **Kubernetes**: 1 control-plane + 3 workers (GCP VMs with nested virtualization)
- **Calico**: iBGP node-to-node mesh (ASN 64512)
- **KubeVirt**: Deployed via `gkm` tool, bridge mode networking

### Virtual Machines

Two VMs are pre-created, each running inside a virt-launcher pod:

| VM  | Description |
|-----|-------------|
| vm1 | The VM we will live-migrate. Runs a TCP streaming server. |
| vm2 | Second VM on a different worker node. Runs a TCP client connected to vm1. |

Run `kubectl get vmi -o wide` to see the actual IPs and node placements.

**Bridge mode networking**: Each VM uses `bridge: {}` interface mode, which means
the VM gets the **exact same IP as its virt-launcher pod**. There is no NAT layer
between the VM and the pod network. The VM is a first-class citizen on the pod network.

The VM spec includes the annotation `kubevirt.io/allow-pod-bridge-network-live-migration: "true"`
which tells KubeVirt to allow live migration even with bridge-mode networking.

### Calico IPAM Configuration

The feature is controlled by a single setting in the IPAMConfig resource:

```yaml
apiVersion: crd.projectcalico.org/v1
kind: IPAMConfig
metadata:
  name: default
spec:
  kubeVirtVMAddressPersistence: Enabled    # <-- This enables the feature
```

When enabled, Calico changes how IP addresses are tracked for KubeVirt VMs:

- **Without the feature**: IPs are allocated per-pod. When a pod is deleted, its IP is released.
  Live migration creates a new pod, which would get a new IP. This breaks VM connectivity.

- **With the feature**: IPs are allocated per-VM using a stable **Handle ID** derived from
  the VM name (format: `k8s-pod-network.vmi.<namespace>.<vm-name>`). The IP persists
  across pod recreation, live migration, and VMI restart.

### What the IPAM State Looks Like

Run this command (it resolves vm1's IP automatically):
```bash
calicoctl ipam show --allow-version-mismatch --ip=$(kubectl get vmi vm1 -o jsonpath='{.status.interfaces[0].ipAddress}')
```

You'll see:

```
IP <VM1_IP> is in use
Handle ID: k8s-pod-network.vmi.default.vm1       <-- Tied to VM name, NOT pod name
Active Owner Attributes:
  namespace: default
  node: <current-node>                            <-- Current node
  pod: virt-launcher-vm1-<hash>                   <-- Current pod
  vm-uid: <vm-uid>
  vmi-name: vm1
  vmi-uid: <vmi-uid>
```

After migration, the same command will show:
- **Same Handle ID** (`k8s-pod-network.vmi.default.vm1`)
- **Same IP**
- **Different node and pod** (the new virt-launcher pod on the destination node)

This is the key proof: the Handle ID is stable, so the IP persists.

---

## How Live Migration Works (What Happens Under the Hood)

When you create a `VirtualMachineInstanceMigration` resource:

1. **KubeVirt creates a target virt-launcher pod** on a different node
2. **Calico CNI allocates the same IP** to the target pod (using the VM-based Handle ID).
   The target pod is registered as the **Alternate Owner** in IPAM.
3. **Felix pre-programs policy and networking** for the target pod but suppresses the
   route (FSM state: Target). Traffic continues to the source node.
4. **Both pods run simultaneously** — source continues serving, target receives VM memory
5. **VM goes live on the destination** — Felix detects the GARP packet and immediately
   programs an **elevated priority route** (metric 512 vs normal 1024). BGP propagates this
   with high LOCAL_PREF so all nodes prefer the new path. The FSM transitions to Live.
6. **Felix swaps IPAM ownership** — the target pod is promoted from Alternate Owner
   to **Active Owner**.
7. **Source pod is terminated** by KubeVirt. After a convergence period (30s),
   Felix reverts to normal route priority (FSM: TimeWait -> Base).

During steps 2-6, both pods have the same IP. Calico tracks both via the
Active/Alternate owner mechanism, ensuring no IP conflicts.

```
  BEFORE MIGRATION                                 AFTER MIGRATION

  +----------------- CLUSTER ----------------+     +----------------- CLUSTER ----------------+
  |                                          |     |                                          |
  |  +-----------+      +-----------+        |     |  +-----------+      +-----------+        |
  |  |  WORKER 0 |      |  WORKER 1 |        |     |  |  WORKER 0 |      |  WORKER 2 |        |
  |  |           |      |           |        |     |  |           |      |           |        |
  |  | +-------+ |      | +-------+ |        |     |  |           |      | +-------+ |        |
  |  | | VM1   | |      | | VM2   | |        |     |  | (VACATED) |      | | VM1   | |        |
  |  | | svr   |<+------+-+ cli   | |        |     |  |           |      | | svr   | |        |
  |  | +-------+ |      | +-------+ |        |     |  |           |      | +-------+ |        |
  |  +-----------+      +-----------+        |     |  +-----------+      +-----^-----+        |
  |                                          |     |                           |              |
  |                     +-----------+        |     |       +-----------+       |              |
  |                     |  WORKER 2 |        |     |       |  WORKER 1 |       |              |
  |                     | (EMPTY)   |        |     |       | +-------+ |       |              |
  |                     +-----------+        |     |       | | VM2   +-+-------+              |
  |                                          |     |       | | cli   | |  seamless!           |
  +------------------------------------------+     |       | +-------+ |                      |
                                                   |       +-----------+                      |
                                                   +------------------------------------------+
```

The key point: VM1 migrates from Worker 0 to Worker 2, keeps the same IP.
The TCP connection from vm2 to vm1 is **seamlessly preserved** with zero drops.
vm2 doesn't notice that vm1 moved to a different node.

---

## Tools

| Tool | Purpose | Location |
|------|---------|----------|
| `virtctl` | KubeVirt CLI — SSH into VMs, trigger migrations | [Install](https://kubevirt.io/user-guide/user_workloads/virtctl_client_tool/) |
| `calicoctl` | Calico CLI — inspect IPAM state | `/usr/local/bin/calicoctl` |
| `kubectl` | Kubernetes CLI — manage resources | Standard |

### Installing calicoctl

The KubeVirt live migration feature added new IPAM commands to calicoctl
(e.g., showing Active/Alternate Owner attributes). 

These changes are not yet in a released version, so we need to build calicoctl from latest calico master and install it locally:
```bash
cd /path/to/calico   # path to the calico repo (e.g., ~/GolandProjects/calico)
git checkout master && git pull origin master
make clean
go build -o bin/calicoctl ./calicoctl/calicoctl/
sudo mv bin/calicoctl /usr/local/bin/calicoctl
```

### Installing virtctl

Install the version matching the cluster's KubeVirt:
```bash
VERSION=$(kubectl get kubevirt -n kubevirt kubevirt -o jsonpath='{.status.observedKubeVirtVersion}')
curl -sL https://github.com/kubevirt/kubevirt/releases/download/$VERSION/virtctl-$VERSION-linux-amd64 -o /tmp/virtctl
chmod +x /tmp/virtctl
sudo mv /tmp/virtctl /usr/local/bin/virtctl
```

### Connecting to VMs with virtctl

```bash
# Set the SSH key used by the cluster VMs
export VM_SSH_KEY=$BZ_ROOT_DIR/.local/crc/kubeadm/1.6/master_ssh_key

# SSH into a VM (uses KubeVirt API — no NodePort service needed)
virtctl ssh ubuntu@vmi/vm1 -i $VM_SSH_KEY -t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null"
virtctl ssh ubuntu@vmi/vm2 -i $VM_SSH_KEY -t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null"

# Trigger a migration
virtctl migrate vm1
```

`virtctl ssh` connects through the KubeVirt API (virt-handler), not through
NodePort services. This means it always reaches the correct running VM, even
after live migration — no stale pod issues.

---

## Quick Start

```bash
# 1. Provision the cluster (creates GCP VMs, installs KubeVirt, deploys Calico, creates VMs)
#    This is a one-time step — skip if the cluster is already running.
./demo/provision-cluster.sh

# 2. Export env vars in your shell (provision-cluster.sh prints these at the end,
#    but they don't persist after the script exits)
export BZ_ROOT_DIR=$PWD/gcp-kubevirt
export KUBECONFIG=$(grep '^KUBECONFIG:' $BZ_ROOT_DIR/Taskvars.yml | awk '{print $2}')

# 3. Launch the 3-pane tmux layout (sets $VM1_IP in all panes)
./demo/tmux-layout.sh

# 5. Follow the commands in the detailed walkthrough below.
#    All commands use env vars that are already set — just copy and paste.
```

---

## Demo Script — Detailed Walkthrough

### Tmux Layout

```
+------------------------------------+------------------------------------+
|  Pane 0 (top-left)                 |  Pane 1 (top-right)               |
|  COMMAND PANE                      |  LIVE WATCH (auto-refreshing)     |
|                                    |                                   |
|  You type/paste commands here.     |  Refreshes every 1s showing:      |
|  kubectl, calicoctl, virtctl       |  - VirtualMachineInstances        |
|                                    |  - Running virt-launcher pods     |
|                                    |  - Active migrations (VMIM)       |
|                                    |  - Calico WorkloadEndpoint (vm1)  |
+------------------------------------+------------------------------------+
|  Pane 2 (bottom)                                                       |
|  VM2 SHELL (already connected via virtctl ssh)                         |
|                                                                        |
|  You are inside vm2. Run: nc <VM1_IP> 9999                             |
|  This starts a single TCP connection to vm1's streaming server.        |
|  During migration the counter should continue with no drops.           |
+------------------------------------------------------------------------+
```

- **Pane 0 (commands)**: Where you run `kubectl`, `calicoctl`, and `virtctl` commands.
  Env vars (`$VM1_IP`, `$KUBECONFIG`, `$BZ_ROOT_DIR`) are pre-set.
- **Pane 1 (watch)**: Auto-refreshing view of VMIs, running pods, active migrations,
  and vm1's WorkloadEndpoint. Completed/succeeded pods are filtered out.
- **Pane 2 (vm2 shell)**: Already SSH'd into vm2 via `virtctl ssh`. You just need
  to run `nc <VM1_IP> 9999` to start the TCP stream. This proves that **intra-cluster
  VM-to-VM connectivity is seamlessly preserved** during live migration — the counter
  continues without interruption, no drops, no reconnections.

### Act 1: Show Bridge Mode, Network Config & Current State (~3 minutes)

**Goal**: Explain the environment, show that the VM IP equals the pod IP (bridge mode),
and show the IPAM Handle ID that enables IP persistence.

**In Pane 0 (top-left)** — `$VM1_IP` is already set by `tmux-layout.sh`.

Run these commands one at a time:

```bash
# 1. Show the running VMs — note the IP column
kubectl get vmi -o wide
```

You'll see both VMs with their IPs and node placements.

**Narrate**: "We have two KubeVirt VMs running with Calico networking in bridge mode."

```bash
# 2. Show the virt-launcher pods — IP column matches the VMI IPs above
kubectl get pods -o wide | grep virt-launcher
```

**Narrate**: "Notice the pod IP is identical to the VM IP. In bridge mode, there is
no NAT between the VM and the pod network. The VM is a first-class network citizen."

```bash
# 3. Show Calico's IPAM state for vm1's IP
calicoctl ipam show --allow-version-mismatch --ip=$VM1_IP
```

**Narrate**: "Here's where it gets interesting. Look at the Handle ID:
`k8s-pod-network.vmi.default.vm1`. This is derived from the VM name, not the pod name.
This is what allows the IP to persist when the pod changes during live migration.
The Active Owner shows which pod currently owns this IP."

---

### Act 2: Start Connection Persistence Test (~2 minutes)

**Goal**: Set up a TCP streaming server on vm1 and a client on vm2 to demonstrate
that intra-cluster connectivity is seamlessly preserved during migration.

#### Step 2a: Start the TCP streaming server on vm1

**In Pane 0 (top-left)**, SSH into vm1 and start the server:

```bash
export VM_SSH_KEY=$BZ_ROOT_DIR/.local/crc/kubeadm/1.6/master_ssh_key
virtctl ssh ubuntu@vmi/vm1 -i $VM_SSH_KEY -t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null"
```

Inside the vm1 SSH session, create the server script and start it:
```bash
cat > /tmp/stream.py << 'PYEOF'
import socket, time, threading
seq = [0]
def handle(c, addr):
    print(f"Connected: {addr}", flush=True)
    try:
        while True:
            seq[0] += 1
            c.sendall(f"[seq={seq[0]:04d}] [time={time.strftime('%H:%M:%S')}] alive\n".encode())
            time.sleep(1)
    except Exception as e:
        print(f"Lost {addr}: {e}", flush=True)
    finally:
        c.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999))
s.listen(5)
print("Streaming server on port 9999", flush=True)
while True:
    c, a = s.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()
PYEOF
PYTHONUNBUFFERED=1 nohup python3 /tmp/stream.py > /tmp/stream.log 2>&1 &
echo "Server started on port 9999"
exit
```

The server uses a **global sequence counter** shared across all connections. If the
connection were to break and a client reconnected, the counter would still increment
— making any gap visible. But with seamless migration, there should be **no gap at all**.

**Narrate**: "I'm starting a TCP streaming server on vm1. It sends a numbered message
every second. We'll connect from vm2 — another VM in the cluster on a different node."

#### Step 2b: Start the client on vm2

**In Pane 0**, note the vm1 IP:
```bash
echo $VM1_IP
```

**In Pane 2 (bottom)** — this pane auto-connects to vm2 via `virtctl ssh`.
Once inside vm2, start the TCP client using the IP from above:

```bash
nc <VM1_IP> 9999
```

You'll see a streaming counter:
```
[seq=0001] [time=19:30:01] alive
[seq=0002] [time=19:30:02] alive
[seq=0003] [time=19:30:03] alive
```

This is a **single TCP connection** — no reconnection loop. During migration,
the stream should continue uninterrupted:

```
[seq=0030] [time=19:31:10] alive
[seq=0031] [time=19:31:11] alive          <-- migration happening
[seq=0032] [time=19:31:12] alive          <-- still connected!
[seq=0033] [time=19:31:13] alive          <-- seamless
```

Leave this running — don't Ctrl+C.

**Narrate**: "Now we have a TCP client on vm2 connected to vm1's streaming server.
This is a single TCP connection — no reconnection logic. If the connection drops,
the stream stops. Let's see what happens when we migrate vm1 to a different node."

---

### Act 3: Initiate Live Migration (~2 minutes)

**Goal**: Trigger the migration and show what happens in real-time.

**In Pane 0 (top-left)**:

```bash
# 1. Clean up completed pods from previous migrations (if any)
kubectl delete pod -l kubevirt.io=virt-launcher --field-selector=status.phase=Succeeded 2>/dev/null

# 2. Confirm which node vm1 is currently on
kubectl get vmi vm1 -o jsonpath='vm1 is on node: {.status.nodeName}{"\n"}'
```

**Narrate**: "vm1 is currently running on node-0. Let's migrate it."

```bash
# 3. Trigger the migration
virtctl migrate vm1
```

Watch **Pane 1 (top-right)** for real-time progress — you'll see a second
`virt-launcher-vm1` pod appear on a different node, and the active migration status.

Also keep an eye on **Pane 2 (bottom)** — the TCP stream should continue without
any interruption throughout the entire migration.

**Narrate while watching**: "KubeVirt is now creating a new virt-launcher pod on a
different node. Both pods are running simultaneously while the VM's memory is being
copied. The migration will progress through phases: Scheduling, TargetReady, Running,
and finally Succeeded. And look at the bottom pane — the TCP stream keeps going,
no drops, no pauses. The connection is alive throughout the migration."

**Narrate**: "Look at the bottom pane — the TCP stream continued without any interruption
during the entire migration. No drops, no reconnections. The connection from vm2 to vm1
stayed up even though vm1 moved to a completely different node. This is seamless live
migration powered by Calico's GARP detection and elevated-priority BGP route advertisement."

---

### Act 4 (OPTIONAL): Show IPAM Ownership Swap (~3 minutes)

**Goal**: Show IPAM state before and after a second migration to demonstrate how
Active/Alternate owner attributes are swapped, and explain how this mechanism
keeps connectivity alive.

**In Pane 0 (top-left)**:

```bash
# 1. Clean up completed pods from previous migration
kubectl delete pod -l kubevirt.io=virt-launcher --field-selector=status.phase=Succeeded 2>/dev/null
```

```bash
# 2. Show current IPAM state — note which node is Active Owner
calicoctl ipam show --allow-version-mismatch --ip=$VM1_IP
```

You'll see:
```
IP <VM1_IP> is in use
Handle ID: k8s-pod-network.vmi.default.vm1
Active Owner Attributes:
  node: <current-node>
  pod: virt-launcher-vm1-<hash>
  vmi-name: vm1
```

**Narrate**: "This is the IPAM state after our first migration. The Active Owner
points to the current pod on the current node. There is no Alternate Owner.
Let's migrate again and see how the ownership changes."

```bash
# 3. Migrate again
virtctl migrate vm1
```

Wait for migration to complete (watch Pane 1 and Pane 2 — the TCP stream should
again continue without interruption).

```bash
# 4. Show IPAM state — the owners have been swapped
calicoctl ipam show --allow-version-mismatch --ip=$VM1_IP
```

Immediately after migration, the owners have been **swapped**:
```
IP <VM1_IP> is in use
Handle ID: k8s-pod-network.vmi.default.vm1       <-- same stable handle
Active Owner Attributes:
  node: <new-node>                                <-- NEW pod is now Active Owner
  pod: virt-launcher-vm1-<new-hash>
  vmi-name: vm1
  vmim-uid: <migration-uid>
Alternate Owner Attributes:
  node: <previous-node>                           <-- OLD pod demoted to Alternate
  pod: virt-launcher-vm1-<old-hash>
  vmi-name: vm1
```

**Narrate**: "Compare the before and after. The Active Owner has changed — it now
points to the new pod on the new node. The previous pod has been demoted to
Alternate Owner."

```bash
# 5. Wait ~10 seconds for source pod cleanup, then check again
sleep 10
calicoctl ipam show --allow-version-mismatch --ip=$VM1_IP
```

After the source pod is deleted, the Alternate Owner is cleared:
```
IP <VM1_IP> is in use
Handle ID: k8s-pod-network.vmi.default.vm1
Active Owner Attributes:
  node: <new-node>
  pod: virt-launcher-vm1-<new-hash>
  vmi-name: vm1
Alternate Owner Attributes:
  <empty>                                         <-- old pod cleaned up
```

**Narrate**: "Now the Alternate Owner is empty — the old source pod has been fully
cleaned up. Only the new Active Owner remains.

Here's how this mechanism keeps connectivity alive:
- **Before migration**: The Active Owner points to the source node. Calico routes
  traffic to that node — this is where the VM is running.
- **During migration**: The target pod is added as Alternate Owner. Both pods share
  the same IP. Traffic keeps flowing to the source (Active Owner) while VM memory
  is copied.
- **At migration completion**: Felix detects the VM is now live on the destination
  (via GARP detection), programs an elevated-priority route to the new node, and
  swaps Active/Alternate owners. Traffic immediately shifts to the new node.
- **After source cleanup**: The old pod is deleted and its Alternate Owner entry
  is removed. Only the new Active Owner remains.

The swap is atomic — there's never a moment where the IP has no owner. That's why
the TCP connection in the bottom pane survived without a single dropped packet."

**Narrate**: "And look at the bottom pane — the TCP stream from vm2 is still going
strong through two migrations. The connection was never broken. That's seamless
live migration."

---

### Act 5 (OPTIONAL): Show Calico Logs (~2 minutes)

**Goal**: Show what Calico did behind the scenes — both the CNI IPAM allocation
and Felix's dataplane programming.

There are two relevant log sources:
1. **CNI IPAM logs** (`/var/log/calico/cni/cni.log` on the node) — show the IP allocation
   and migration target detection
2. **Felix logs** (calico-node container logs) — show the workload endpoint programming

```bash
./demo/show-calico-logs.sh
```

This script auto-detects vm1's current node, then shows two sets of logs from
that node's calico-node pod: Felix logs (live migration FSM transitions, GARP
detection, IPAM ownership swap) and CNI IPAM logs (migration target detection,
IP reuse, route skipping). Long fields like container IDs are trimmed for
readability.

Key log lines to look for:

**Felix FSM** — shows the full live migration state machine:
```
Base → Target                          (migration started)
Detected GARP/RARP packet              (VM became active on destination)
Target → Live (GARPDetected)           (elevated-priority route programmed)
Successfully swapped IPAM owner attrs  (ownership transferred)
Live → TimeWait                        (migration complete)
TimeWait → Base                        (30s convergence timer expired)
```

**CNI IPAM** — shows migration detection and IP reuse:
```
Detected KubeVirt virt-launcher pod, using VM-based handle ID ... isMigrationTarget=true
Calico CNI using IPs: [<VM1_IP>/32]
Skipping host-side route setup (skipHostSideRoutes=true)
```

**Narrate**: "Looking at the Calico logs on the destination node, we can see exactly
what happened. The CNI plugin detected this was a migration target pod and reused
the VM's existing IP. Felix detected the GARP packet when the VM became active,
immediately programmed an elevated-priority route, and swapped the IPAM ownership.
The whole handover happened in milliseconds — that's why the TCP connection survived."

---


## Files in This Directory

| File | Purpose |
|------|---------|
| `README.md` | This file — full demo guide |
| `provision-cluster.sh` | Provisions the GCP cluster, installs KubeVirt, deploys Calico, creates VMs, and validates |
| `tmux-layout.sh` | Launches 3-pane tmux layout, sets `$VM1_IP` in all panes |


| `show-calico-logs.sh` | Auto-detects vm1's node, shows Felix FSM transitions (GARP detection, IPAM swap) and CNI IPAM logs (migration target detection, IP reuse) with trimmed output |
