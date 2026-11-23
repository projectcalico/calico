# Guardian glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `guardian/`, which builds the `calico component guardian` command of this repository.

## Building blocks

The top layer of Guardian.

| Building block | Code | Responsible for |
|---|---|---|
| Daemon | `guardian/pkg/daemon/daemon.go` (`Run`) | Creates the tunnel and the proxy, then starts the upstream and downstream paths. |
| Server | `guardian/pkg/server/server.go` (`ListenAndServeCluster`) | Forwards in-cluster connections up the tunnel, and serves tunneled HTTP that arrives down it. |
| Proxy | `guardian/pkg/server/proxy.go` (`Proxy`) | Path-prefix reverse proxy to the Kubernetes API and to Goldmane's `Statistics/List`. |
| Tunnel | `guardian/pkg/tunnel/tunnel.go` (`Tunnel`) | A yamux-multiplexed mTLS session in which either side can open streams. |
| Async command runner | `guardian/pkg/asyncutil/async.go` (`CommandExecutor`) | Generic asynchronous command execution used by the tunnel. |

## Terms

**Guardian**:
The agent in a cluster that holds one mTLS tunnel to a management cluster.
Code: `guardian/pkg/daemon/daemon.go` (`Run`).
_Avoid_: tunnel client, agent, the tunnel

**Management cluster**:
The cluster at the far end of Guardian's tunnel. Its server is not in this repository.
Code: `guardian/pkg/config/config.go` (`VoltronURL`).
_Avoid_: remote cluster

**Tunnel session**:
One yamux session over mTLS to the management cluster, on which either side opens streams.
Code: `guardian/pkg/tunnel/dial.go` (`Session`).
_Avoid_: connection

**Upstream path**:
The path from the cluster to the management cluster.
Code: `guardian/pkg/server/server.go` (`ListenAndServeCluster`).
_Avoid_: outbound, cluster listener

**Downstream path**:
The path from the management cluster to the cluster.
Code: `guardian/pkg/server/server.go` (`ListenAndServeManagementCluster`).
_Avoid_: inbound, management cluster listener

**Target**:
A path prefix mapped to a destination URL, with token, CA and mTLS options.
Code: `guardian/pkg/server/target.go` (`Target`).
_Avoid_: route
