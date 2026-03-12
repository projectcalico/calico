# KubeVirt Live Migration Demo for KubeCon Europe 2026

## What This Demo Shows

Calico now supports **IP address persistence for KubeVirt VMs** across live migrations.
When a VM live-migrates from one node to another, Calico ensures:

- The VM keeps the **exact same IP address** on the new node
- **Active network connections are not dropped** during migration
- **No manual intervention** is needed — Calico handles IPAM and routing automatically

This is critical for production VM workloads that expect stable IP addresses
(databases, stateful services, long-lived connections).

---

## Environment Overview

### Cluster Architecture

```
  ┌──────────────────── KUBERNETES CLUSTER ───────────────────┐
  │                                                           │
  │  ┌────────────────────┐                                   │
  │  │   CONTROL PLANE    │                                   │
  │  │   ASN 64512        │                                   │
  │  └────────────────────┘                                   │
  │                                                           │
  │  ┌────────────┐   ┌────────────┐    ┌────────────┐        │
  │  │  WORKER 0  │   │  WORKER 1  │    │  WORKER 2  │        │
  │  │            │   │            │    │            │        │
  │  │  ┌──────┐  │   │  ┌──────┐  │    │ (MIGRATION │        │
  │  │  │ VM1  │  │   │  │ VM2  │  │    │  TARGET)   │        │
  │  │  └──────┘  │   │  └──────┘  │    │            │        │
  │  └────────────┘   └────────────┘    └────────────┘        │
  │                                                           │
  │  CALICO: BGP, IPTABLES DATAPLANE                          │
  │  KUBEVIRT: BRIDGE MODE NETWORKING                         │
  └────────────────────────────┬──────────────────────────────┘
                               │
                        L2TP TUNNELS
                       (172.16.8.0/24)
                               │
              ┌────────────────┼────────────────┐
              │                                 │
     ┌────────┴────────┐              ┌─────────┴───────┐
     │     SERVER      │              │      TOR        │
     │  (EXTERNAL-0)   │              │  (EXTERNAL-1)   │
     │                 │              │                 │
     │   L2TP HUB      │              │  BIRD BGP       │
     │                 │              │  ASN 63000      │
     └─────────────────┘              └─────────────────┘
```

- **Kubernetes**: 1 control-plane + 3 workers (GCP VMs with nested virtualization)
- **Calico**: BGP node-to-node mesh (ASN 64512)
- **KubeVirt**: Deployed via `gkm` tool, bridge mode networking
- **L2TP tunnels**: Connect all nodes and external hosts on 172.16.8.0/24
- **TOR node**: External GCP VM running BIRD BGP (ASN 63000), peers with all cluster nodes
- **Server node**: L2TP tunnel hub

### Virtual Machines

Two VMs are pre-created, each running inside a virt-launcher pod:

| VM  | Description |
|-----|-------------|
| vm1 | The VM we will live-migrate. Runs on one worker node. |
| vm2 | Second VM on a different worker node. Not used in the demo. |

Run `kubectl get vmi -o wide` to see the actual IPs and node placements.

The **TOR node** (external to the cluster) is used as the TCP stream client to prove
that connections from outside the cluster survive migration via BGP route updates.

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
calicoctl ipam show --ip=$(kubectl get vmi vm1 -o jsonpath='{.status.interfaces[0].ipAddress}')
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
3. **Both pods run simultaneously** — source continues serving, target receives VM memory
4. **KubeVirt completes the migration** — VM is now running on the target pod
5. **Felix detects migration completion** and promotes the target pod from
   Alternate Owner to **Active Owner** in IPAM. Routes are updated automatically.
6. **Source pod is terminated** by KubeVirt

During steps 2-5, both pods have the same IP. Calico tracks both via the
Active/Alternate owner mechanism, ensuring no IP conflicts.

```
  BEFORE MIGRATION                                        AFTER MIGRATION

  ┌──────────────────── CLUSTER ───────────────-───┐       ┌──────────────────── CLUSTER ──────────────-────┐
  │                                                │       │                                                │
  │  ┌──────────────────────────────────────────┐  │       │  ┌──────────────────────────────────────────┐  │
  │  │             CONTROL PLANE                │  │       │  │             CONTROL PLANE                │  │
  │  └──────────────────────────────────────────┘  │       │  └──────────────────────────────────────────┘  │
  │                                                │       │                                                │
  │  ┌─────────────────┐   ┌─────────────────┐     │       │  ┌─────────────────┐   ┌─────────────────┐     │
  │  │    WORKER 0     │   │    WORKER 2     │     │       │  │    WORKER 0     │   │    WORKER 2     │     │
  │  │                 │   │                 │     │       │  │                 │   │                 │     │
  │  │  ┌───────────┐  │   │  (MIGRATION     │     │       │  │                 │   │  ┌───────────┐  │     │
  │  │  │    VM1    │  │   │   TARGET)       │     │       │  │   (VACATED)     │   │  │    VM1    │  │     │
  │  │  │   IP:X    │━━╋━━━╋━━▶              │     │       │  │                 │   │  │   IP:X    │  │     │
  │  │  └───────────┘  │   │                 │     │       │  │                 │   │  └───────────┘  │     │
  │  │       ▲         │   └─────────────────┘     │       │  └─────────────────┘   └───────▲─────────┘     │
  │  └───────┃─────────┘                           │       │                                ┃               │
  │          ┃                                     │       │                                ┃               │
  │          ┃     ┌─────────────────┐             │       │       ┌─────────────────┐      ┃               │
  │          ┃     │    WORKER 1     │             │       │       │    WORKER 1     │      ┃               │
  │          ┃     │  ┌───────────┐  │             │       │       │  ┌───────────┐  │      ┃               │
  │          ┃     │  │    VM2    │  │             │       │       │  │    VM2    │  │      ┃               │
  │          ┃     │  └───────────┘  │             │       │       │  └───────────┘  │      ┃               │
  │          ┃     └─────────────────┘             │       │       └─────────────────┘      ┃               │
  │          ┃                                     │       │                                ┃               │
  └──────────╋─────────────────────────────────────┘       └────────────────────────────────╋───────────────┘
             ┃                                                                              ┃
             ┃  TCP STREAM TO VM1 (VIA BGP)                             SAME TCP CONNECTION,┃
             ┃                                                          NEVER DROPPED       ┃
             ┃                                                                              ┃
  ┌──────────┃───────────┐   ┌─────────────────┐       ┌─────────────────┐   ┌────────-─────┃───────┐
  │  TOR (EXTERNAL)      │   │     SERVER      │       │     SERVER      │   │  TOR (EXTERNAL)      │
  │  ┌────────────────┐  │   │                 │       │                 │   │  ┌────────────────┐  │
  │  │   BIRD BGP     │  │   │    L2TP HUB     │       │    L2TP HUB     │   │  │   BIRD BGP     │  │
  │  │   ASN 63000    │  │   │                 │       │                 │   │  │   ASN 63000    │  │
  │  └────────────────┘  │   └─────────────────┘       └─────────────────┘   │  └────────────────┘  │
  └──────────────────────┘                                                   └──────────────────────┘
```

The key point: VM1 migrates from Worker 0 to Worker 2, keeps the same IP. The
persistent TCP connection from the TOR node (outside the cluster, via BGP) is never
dropped — BGP routes converge and traffic flows to the new node automatically.

---

## Tools

| Tool | Purpose | Location |
|------|---------|----------|
| `gkm` | GCP KubeVirt Manager — SSH into nodes/VMs/external hosts, manage cluster | `/usr/local/bin/gkm` |
| `calicoctl` | Calico CLI — inspect IPAM state | `/usr/local/bin/calicoctl` |
| `kubectl` | Kubernetes CLI — manage resources | Standard |

### gkm Commands Used in Demo

```bash
# REQUIRED: Set this before using gkm
export BZ_ROOT_DIR=/path/to/your/gcp-kubevirt-cluster

gkm connect vm1     # Interactive SSH session into vm1
gkm connect vm2     # Interactive SSH session into vm2
gkm connect node-0  # SSH into worker node 0

# For the TOR node (non-cluster GCP instance), use gcloud:
# $TOR_INSTANCE and $TOR_ZONE are set automatically by tmux-layout.sh
gcloud compute ssh ubuntu@$TOR_INSTANCE --zone=$TOR_ZONE
```

`gkm connect <vm>` opens an **interactive** SSH session. You type commands inside
the VM, then `exit` to return. It does not support inline commands like
`gkm connect vm1 -- 'some command'`.

---

## Quick Start

```bash
# 1. Set BZ_ROOT_DIR (cluster dir with .local/ and Taskvars.yml — provided by cluster owner)
export BZ_ROOT_DIR=/path/to/cluster-dir

# 2. Run setup (validates cluster, creates BGPPeer)
#    KUBECONFIG is read from Taskvars.yml automatically.
./demo/setup.sh

# 3. Launch the 3-pane tmux layout (sets $VM1_IP, $TOR_INSTANCE, $TOR_ZONE in all panes)
./demo/tmux-layout.sh

# 4. Follow the commands in the detailed walkthrough below.
#    All commands use env vars that are already set — just copy and paste.
#    The ONLY exception: the `nc` command on the TOR node needs the real IP.
#    Run `echo $VM1_IP` before SSH-ing to TOR, then use that IP for `nc`.
```

---

## Demo Script — Detailed Walkthrough

### Tmux Layout

```
+------------------------------------+------------------------------------+
|  Pane 0 (top-left)                 |  Pane 1 (top-right)               |
|  COMMAND PANE                      |  LIVE WATCH (auto-started)        |
|                                    |                                   |
|  You type/paste commands here.     |  Refreshes every 1s showing:      |
|  kubectl, calicoctl, gkm connect   |  - VirtualMachineInstances        |
|                                    |  - Virt-launcher pods + nodes     |
+------------------------------------+------------------------------------+
|  Pane 2 (bottom)                                                       |
|  TCP STREAM (persistent connection from TOR node, outside the cluster) |
|                                                                        |
|  A SINGLE TCP connection from the external TOR node to vm1 via BGP.    |
|  The counter keeps incrementing through migration — proof it survived. |
+------------------------------------------------------------------------+
```

- **Pane 2 (TCP stream)**: Proves a **single persistent TCP connection from outside the
  cluster** survives the migration. The TOR node connects to vm1 via BGP routing. This is
  the proof, an external client that established a connection BEFORE migration
  continues to receive data AFTER migration without reconnecting.

### Act 1: Show Bridge Mode, Network Config & Current State (~3 minutes)

**Goal**: Explain the environment, show that the VM IP equals the pod IP (bridge mode),
and show the IPAM Handle ID that enables IP persistence.

**In Pane 0 (top-left)** — `$VM1_IP`, `$TOR_INSTANCE`, and `$TOR_ZONE` are already
set by `tmux-layout.sh`. All commands below use these variables directly.

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
calicoctl ipam show --ip=$VM1_IP
```

**Narrate**: "Here's where it gets interesting. Look at the Handle ID:
`k8s-pod-network.vmi.default.vm1`. This is derived from the VM name, not the pod name.
This is what allows the IP to persist when the pod changes during live migration.
The Active Owner shows which pod currently owns this IP."

```bash
# 4. Show the Calico WorkloadEndpoint for vm1 — this IS the network configuration
calicoctl get workloadendpoint -o wide | grep vm1
```

Expected output:
```
...-node--0-k8s-virt--launcher--vm1--ss84x-eth0   virt-launcher-vm1-ss84x   node-0   <VM1_IP>/32   calie43e169e946   kns.default,ksa.default.default
```

**Narrate**: "This is vm1's WorkloadEndpoint — Calico's representation of the VM's
network config. It shows the IP, interface, profiles, and the node it's on. We'll
compare this after migration."

---

### Act 2: Start Connection Persistence Monitor (~2 minutes)

**Goal**: Set up a persistent TCP connection that proves connections survive migration.

#### Step 2a: Start the TCP streaming server on vm1

**In Pane 0 (top-left)**, SSH into vm1 and start the server:

```bash
gkm connect vm1
```

Inside the vm1 SSH session, copy the server script and start it:
```bash
cat > /tmp/stream.py << 'PYEOF'
import socket, time, threading
def handle(c):
    seq = 1
    try:
        while True:
            c.sendall(f"[seq={seq:04d}] [time={time.strftime('%H:%M:%S')}] Connection alive - VM1 streaming...\n".encode())
            seq += 1; time.sleep(1)
    except: pass
    finally: c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999)); s.listen(5)
print(f"Streaming server on port 9999...")
while True:
    c, a = s.accept(); print(f"Client: {a}"); threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF
nohup python3 /tmp/stream.py > /dev/null 2>&1 & exit
```

**Narrate**: "I'm starting a TCP streaming server on vm1. It sends a counter every
second to any connected client. We'll connect from the TOR node — that's a machine
outside the cluster that reaches vm1 via BGP. If the connection survives migration,
it proves BGP routes converge correctly."

#### Step 2b: Connect the TCP stream client from the TOR node

**In Pane 2 (bottom)** — `$TOR_INSTANCE`, `$TOR_ZONE`, and `$VM1_IP` are already
set by `tmux-layout.sh`. SSH into the TOR node and connect to vm1's TCP stream:
```bash
echo $VM1_IP
gcloud compute ssh ubuntu@$TOR_INSTANCE --zone=$TOR_ZONE
```
Then on the TOR node (use the IP printed above):
```bash
nc <vm1-ip> 9999
```

You'll see a streaming counter:
```
[seq=0001] [time=19:30:01] Connection alive - VM1 streaming...
[seq=0002] [time=19:30:02] Connection alive - VM1 streaming...
[seq=0003] [time=19:30:03] Connection alive - VM1 streaming...
```

**This is a SINGLE persistent TCP connection.** If it survives migration, the sequence
number will keep incrementing without gap. If the connection drops, the output stops.

Leave this running — don't Ctrl+C.

**Narrate**: "Now we have a persistent TCP connection from an external node to vm1,
routed via BGP. If this connection survives the migration, it proves that not only
does the IP persist, but BGP routes update correctly so external clients never lose
connectivity. Let's migrate vm1."

---

### Act 3: Initiate Live Migration (~2 minutes)

**Goal**: Trigger the migration and show what happens in real-time.

**In Pane 0 (top-left)**:

```bash
# 1. Confirm which node vm1 is currently on
kubectl get vmi vm1 -o jsonpath='vm1 is on node: {.status.nodeName}{"\n"}'
```

**Narrate**: "vm1 is currently running on node-0. Let's migrate it."

```bash
# 2. Create the migration resource
kubectl create -f demo/migrate-vm1.yaml
```

This creates a `VirtualMachineInstanceMigration` that tells KubeVirt to move vm1
to another node. The manifest is simple:

```yaml
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstanceMigration
metadata:
  name: migration-vm1
spec:
  vmiName: vm1
```

```bash
# 3. Watch migration progress
kubectl get vmim -w
```

**Narrate while watching**: "KubeVirt is now creating a new virt-launcher pod on a
different node. Watch the top-right pane — you'll see a second virt-launcher-vm1 pod
appear. Both pods are running simultaneously while the VM's memory is being copied.
And look at the bottom pane — the TCP stream counter keeps incrementing."

The migration status will progress through phases:
- `Scheduling` → `Scheduled` → `PreparingTarget` → `TargetReady` → `Running` → `Succeeded`

Press **Ctrl+C** once you see `Succeeded`.

**What to point out during migration**:
- **Pane 1 (watch)**: A new `virt-launcher-vm1-XXXXX` pod appears on a different node
- **Pane 2 (TCP stream)**: The counter keeps incrementing — the persistent connection is ALIVE
- **Pane 0**: Migration status progressing

**Narrate**: "Look at the bottom pane — the TCP stream counter is still incrementing.
That's a single persistent connection that was established before the migration,
and it's still alive. The connection was never dropped."

---

### Act 4: Verify IP Preservation AND Network Config Retention (~3 minutes)

**Goal**: Prove the IP was preserved, the IPAM state transferred correctly,
AND the full network configuration (workload endpoint, policy) still applies.

**In Pane 0 (top-left)**:

```bash
# 1. Show VMs — vm1 is now on a different node but SAME IP
kubectl get vmi -o wide
```

**Narrate**: "vm1 has moved to a different node, but look — the IP address is still
<VM1_IP>. It didn't change."

```bash
# 2. Show pods — new pod name, new node, same IP
kubectl get pods -o wide | grep virt-launcher
```

**Narrate**: "The virt-launcher pod has a new name and is running on a new node,
but the IP is identical."

```bash
# 3. Show IPAM state — this is the key proof
calicoctl ipam show --ip=$VM1_IP
```

**Narrate**: "Now look at the Calico IPAM state. The Handle ID is still
`k8s-pod-network.vmi.default.vm1` — unchanged. But the Active Owner now points to the
new pod on the new node. Calico automatically detected the migration completed and
transferred IP ownership to the new pod. No manual intervention required."

```bash
# 4. Show the WorkloadEndpoint AFTER migration — compare with Act 1
calicoctl get workloadendpoint -o wide | grep vm1
```

**Narrate**: "The WorkloadEndpoint has been recreated on the new node. Notice the
IP is the same (<VM1_IP>/32), the profiles are the same (kns.default,
ksa.default.default), and the labels are the same — but the node and interface have
changed to reflect the new location. All the network configuration migrated with the VM."

**Narrate**: "And look at the bottom pane — the TCP stream counter from the
external TOR node kept incrementing through the migration. An external client,
routing via BGP, never lost its connection."

---

### Act 5: Show Calico Logs (~2 minutes)

**Goal**: Show what Calico did behind the scenes — both the CNI IPAM allocation
and Felix's dataplane programming.

There are two relevant log sources:
1. **CNI IPAM logs** (`/var/log/calico/cni/cni.log` on the node) — show the IP allocation
   and migration target detection
2. **Felix logs** (calico-node container logs) — show the workload endpoint programming

Use the helper script:
```bash
./demo/show-calico-logs.sh
```

Or run the commands manually:

```bash
# Find Felix pod on destination node
DEST_NODE=$(kubectl get vmi vm1 -o jsonpath='{.status.nodeName}')
FELIX_POD=$(kubectl get pods -n calico-system -l k8s-app=calico-node \
  --field-selector spec.nodeName=$DEST_NODE -o jsonpath='{.items[0].metadata.name}')
```

**CNI IPAM logs** (the most interesting — shows migration detection and IP reuse):
```bash
kubectl exec -n calico-system $FELIX_POD -c calico-node -- \
  grep "virt-launcher-vm1" /var/log/calico/cni/cni.log | tail -15
```

Key log lines to look for:
```
Detected KubeVirt virt-launcher pod, using VM-based handle ID ... isMigrationTarget=true
```
This shows the CNI plugin detected the new pod is a **migration target** (not a fresh VM).

```
Reusing existing IPs for VM handle ... HandleID="k8s-pod-network.vmi.default.vm1"
```
This shows the CNI plugin **reused the same IP** from the existing VM handle instead of
allocating a new one.

```
Calico CNI IPAM assigned addresses IPv4=[<VM1_IP>/26]
```
The same IP was assigned to the target pod.

**Felix logs** (shows iptables/route programming):
```bash
kubectl logs -n calico-system $FELIX_POD -c calico-node --tail=200 | \
  grep "virt-launcher-vm1"
```

Key log lines:
```
Received *proto.WorkloadEndpointUpdate update from calculation graph
  ... workload_id:"default/virt-launcher-vm1-XXXXX" ... ipv4_nets:"<VM1_IP>/32"
Updating per-endpoint chains   id=...virt-launcher-vm1-XXXXX...
Updating endpoint routes       id=...virt-launcher-vm1-XXXXX...
Endpoint up ... status="up"    workload=...virt-launcher-vm1-XXXXX...
```

**Narrate**: "Looking at the Calico logs on the destination node, we can see exactly
what happened. The CNI plugin detected this was a migration target pod and reused
the VM's existing IP. Then Felix received the new WorkloadEndpoint, programmed the
iptables chains and routes, and the endpoint came up. All automatic, all within seconds."

---

## Cleanup After Recording

```bash
kubectl delete vmim migration-vm1
```

---

## Files in This Directory

| File | Purpose |
|------|---------|
| `README.md` | This file — full demo guide |
| `setup.sh` | Validates cluster, creates BGPPeer for TOR node |
| `tmux-layout.sh` | Launches 3-pane tmux layout, sets `$VM1_IP`, `$TOR_INSTANCE`, `$TOR_ZONE` in all panes |
| `cheatsheet.txt` | Template cheatsheet with env var references |
| `migrate-vm1.yaml` | VirtualMachineInstanceMigration manifest to trigger vm1 migration |
| `show-calico-logs.sh` | Shows CNI IPAM + Felix logs from the migration |