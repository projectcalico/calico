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
The calico-node networking mode, one of `bird`, `vxlan` or `none`.
Code: `node/filesystem/etc/rc.local`.
_Avoid_: backend (on its own), policy-only mode

**Autodetection method**:
The rule for choosing the Calico node address from the host's interfaces: `first-found`, `interface=`, `cidr=`, `can-reach=`, `skip-interface=` or `kubernetes-internal-ip`.
Code: `node/pkg/lifecycle/startup/autodetection/autodetection_methods.go` (`AUTODETECTION_METHOD_FIRST`, `AUTODETECTION_METHOD_CAN_REACH`).
_Avoid_: autodetect, detection method

**Default pools**:
The IP pools that calico-node creates at first startup.
Code: `node/pkg/lifecycle/startup/startup.go` (`configureIPPools`).
_Avoid_: default IP pool

**Node name file**:
The file `/var/lib/calico/nodename`, which holds the v3.Node name for this host. In a Kubernetes cluster that is the node name.
Code: `node/pkg/lifecycle/utils/utils.go` (`NodenameFromFile`, `DetermineNodeName`).
_Avoid_: nodename file, node name on its own (that is the Kubernetes Node)

**Shutdown timestamp file**:
The file `/var/lib/calico/shutdownTS`, written at shutdown.
Code: `node/pkg/lifecycle/utils/utils.go` (`defaultShutdownTimestampFileLinux`).
_Avoid_: shutdownTS

**Complete-startup**:
The node-services task that marks the node's network available.
Code: `node/pkg/lifecycle/startup/startup.go` (`ManageNodeCondition`, `MarkNetworkAvailable`).
_Avoid_: startup on its own (that is the earlier init step)

**Monitor-addresses**:
The node-services task that keeps the Node resource's Calico node address current.
Code: `node/pkg/lifecycle/startup/startup.go` (`MonitorIPAddressSubnetsWithContext`).
_Avoid_: address monitor

**Tunnel IP allocator**:
The node-services task that manages the node's tunnel addresses.
Code: `node/pkg/allocateip/allocateip.go` (`Run`, `reconcileTunnelAddrs`).
_Avoid_: allocateip

**Status reporter**:
The node-services task that fills the CalicoNodeStatus resource from BIRD's control socket.
Code: `node/pkg/status/nodestatus.go` (`RunWithContext`).
_Avoid_: reporter (it means several things)

**BIRD control socket**:
The Unix socket, `/var/run/calico/bird.ctl` for IPv4 and `bird6.ctl` for IPv6, on which BIRD answers queries.
Code: `node/pkg/health/bird/bird.go` (`GetPeers`, `GRInProgress`).
_Avoid_: bird.ctl, BIRD socket

**Graceful restart**:
BIRD's ability to restart without withdrawing its routes.
Code: `node/filesystem/etc/service/available/bird/run`.
_Avoid_: GR

**BIRD startup readiness window**:
The period after calico-node starts in which BIRD's readiness check is stricter than it is afterward.
Code: `node/pkg/health/health.go` (`checkBIRDReady`).
_Avoid_: nothing known

**NetworkUnavailable condition**:
The Kubernetes node condition that reports whether the node's network is unavailable, set by calico-node.
Code: `node/pkg/lifecycle/utils/utils.go` (`SetNodeNetworkUnavailableCondition`), `node/pkg/lifecycle/shutdown/shutdown.go` (`Run`).
_Avoid_: taint (that is a different node mechanism)

## Words that need a qualifier

| Word | Meanings in play | Say |
|---|---|---|
| backend | the networking backend, the datastore backend | networking backend, datastore backend |
| node | the Kubernetes Node, the v3.Node, the machine | node name, v3.Node name, host |
| component | a `calico component <name>` subcommand, a runit service | subcommand, runit service |
