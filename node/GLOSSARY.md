# calico-node glossary

This file extends the [root GLOSSARY.md](../GLOSSARY.md). It covers the calico-node image and its startup, services, tunnel address allocation and health checks. The programs it runs have their own files: [felix/GLOSSARY.md](../felix/GLOSSARY.md) and [confd/GLOSSARY.md](../confd/GLOSSARY.md).

## Building blocks

Top layer of calico-node.

| Building block | Code | Responsible for |
|---|---|---|
| rc.local | `node/filesystem/etc/rc.local` | The container's init script: it runs startup, allocates tunnel addresses and enables the runit services the networking backend needs. |
| Runit services | `node/filesystem/etc/service/available/` | One supervised process each for `felix`, `bird`, `bird6`, `confd` and `node-services`. |
| Node command | `node/pkg/node/command.go` (`NewCommand`) | The `calico component node` command tree: init, startup, shutdown, node-services, allocate-tunnel-addrs, health and status. |
| Startup | `node/pkg/lifecycle/startup/startup.go` (`Run`) | Choosing the node name, setting the Calico node address and AS number, and creating the default pools and default configuration. |
| Node services | `node/pkg/nodeservices/nodeservices.go` (`Run`) | Running complete-startup, the tunnel IP allocator, the status reporter, monitor-addresses and the CNI token monitor in one process. |
| Health | `node/pkg/health/health.go` (`RunOutput`, `checkBIRDReady`) | Readiness and liveness checks for Felix and BIRD. |
| Shutdown | `node/pkg/lifecycle/shutdown/shutdown.go` (`Run`) | Writing the shutdown timestamp file and setting `NetworkUnavailable` to true. |

Layers inside startup and node services.

| Building block | Code | Responsible for |
|---|---|---|
| IP autodetection | `node/pkg/lifecycle/startup/autodetection/autodetection_methods.go` (`AutoDetectCIDR`) | Picking the Calico node address from the host's interfaces by an autodetection method. |
| Default pools | `node/pkg/lifecycle/startup/startup.go` (`configureIPPools`) | Creating the default IPv4 and IPv6 pools from the `CALICO_IPV4POOL_*` settings and kubeadm configuration. |
| Complete-startup | `node/pkg/lifecycle/startup/startup.go` (`ManageNodeCondition`) | Waiting for Felix and BIRD to be ready, then clearing the `NetworkUnavailable` condition. |
| Monitor-addresses | `node/pkg/lifecycle/startup/startup.go` (`MonitorIPAddressSubnetsWithContext`) | Re-running autodetection on a poll interval and updating the Node resource. |
| Tunnel IP allocator | `node/pkg/allocateip/allocateip.go` (`Run`, `reconcileTunnelAddrs`) | Allocating the IPIP, VXLAN and WireGuard tunnel addresses from IPAM and writing them to the Node. |
| Status reporter | `node/pkg/status/nodestatus.go` (`RunWithContext`) | Filling CalicoNodeStatus from BIRD's control socket. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Calico node address](../GLOSSARY.md#calico-node-address)
- [Tunnel address](../GLOSSARY.md#tunnel-address)

**Networking backend**:
The `CALICO_NETWORKING_BACKEND` value, `bird`, `vxlan` or `none`, that decides whether rc.local enables confd and BIRD. With `vxlan` or `none`, neither runs.
Code: `node/filesystem/etc/rc.local`.
_Avoid_: backend (on its own), policy-only mode

**Autodetection method**:
The rule, set by `IP_AUTODETECTION_METHOD`, that picks the Calico node address from the host's interfaces: `first-found`, `interface=`, `cidr=`, `can-reach=`, `skip-interface=` or `kubernetes-internal-ip`.
Code: `node/pkg/lifecycle/startup/autodetection/autodetection_methods.go` (`AUTODETECTION_METHOD_FIRST`, `AUTODETECTION_METHOD_CAN_REACH`).

**Default pools**:
The IP pools startup creates when none exist, from the `CALICO_IPV4POOL_*` and `CALICO_IPV6POOL_*` settings and the kubeadm cluster configuration.
Code: `node/pkg/lifecycle/startup/startup.go` (`configureIPPools`).

**Node name file**:
The file `/var/lib/calico/nodename`. Startup writes the v3.Node name it chose, which in a Kubernetes cluster is the node name, and rc.local, health and later starts read it. Its modification time starts the BIRD startup readiness window.
Code: `node/pkg/lifecycle/utils/utils.go` (`NodenameFromFile`, `DetermineNodeName`).

**Shutdown timestamp file**:
The file `/var/lib/calico/shutdownTS`. Shutdown writes it, and complete-startup removes it once startup succeeds.
Code: `node/pkg/lifecycle/utils/utils.go` (`defaultShutdownTimestampFileLinux`).

**Complete-startup**:
The node-services task that waits for Felix and BIRD to be ready, then clears the Kubernetes `NetworkUnavailable` condition on the node.
Code: `node/pkg/lifecycle/startup/startup.go` (`ManageNodeCondition`, `MarkNetworkAvailable`).

**Monitor-addresses**:
The node-services task that re-runs autodetection every poll interval and updates the Node resource when the Calico node address changes.
Code: `node/pkg/lifecycle/startup/startup.go` (`MonitorIPAddressSubnetsWithContext`).

**Tunnel IP allocator**:
The node-services task that keeps each enabled tunnel address allocated, and releases it when its tunnel is disabled.
Code: `node/pkg/allocateip/allocateip.go` (`Run`, `reconcileTunnelAddrs`).

**Status reporter**:
The node-services task that fills the CalicoNodeStatus resource from BIRD's control socket.
Code: `node/pkg/status/nodestatus.go` (`RunWithContext`).

**BIRD control socket**:
The Unix socket, `/var/run/calico/bird.ctl` for IPv4 and `bird6.ctl` for IPv6, through which health, the status reporter and calicoctl query BIRD.
Code: `node/pkg/health/bird/bird.go` (`GetPeers`, `GRInProgress`).

**Graceful restart**:
BIRD's restart handling. The `bird` runit service starts BIRD with `-R`, and the kernel protocol persists routes, so a BIRD restart does not withdraw them.
Code: `node/filesystem/etc/service/available/bird/run`.

**BIRD startup readiness window**:
The period after calico-node starts, counted from the node name file's modification time, in which BIRD reports ready only when every peering is Established and no graceful restart is running. After the window, one Established peering is enough.
Code: `node/pkg/health/health.go` (`checkBIRDReady`).

**NetworkUnavailable condition**:
The Kubernetes node condition that calico-node sets true at shutdown and clears once Felix and BIRD are ready.
Code: `node/pkg/lifecycle/utils/utils.go` (`SetNodeNetworkUnavailableCondition`), `node/pkg/lifecycle/shutdown/shutdown.go` (`Run`).

## Words that need a qualifier

| Word | Meanings in play | Say |
|---|---|---|
| backend | the networking backend, the datastore backend | networking backend, datastore backend |
| node | the Kubernetes Node, the v3.Node, the machine | node name, v3.Node name, host |
| component | a `calico component <name>` subcommand, a runit service | subcommand, runit service |
