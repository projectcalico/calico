# Typha glossary

This file extends the [root GLOSSARY.md](../GLOSSARY.md). Words that Typha shares with other components (datastore, syncer, in-sync, KVPair) are defined there.

## Building blocks

Top layer of Typha. The second table lists the stages inside the syncer pipeline and the sync server.

| Building block | Code | Responsible for |
|---|---|---|
| Syncer pipeline | `typha/pkg/daemon/daemon.go` (`syncerPipeline`) | One per syncer type: the chain from a datastore syncer to a snapshot cache. |
| Sync server | `typha/pkg/syncserver/sync_server.go` (`Server`) | Accepting client connections, enforcing the connection limit, and shutting down gracefully. |
| Rebalancer | `typha/pkg/k8s/rebalance.go` (`PollK8sForConnectionLimit`, `CalculateMaxConnLimit`) | Setting each Typha's connection limit from the Typha count and the node count. |
| Sync client library | `typha/pkg/syncclient/sync_client.go` (`SyncerClient`) | The client end of the protocol, run inside Felix, confd and calico-node. |
| Discovery | `typha/pkg/discovery/discovery.go` (`Discoverer`) | Finding Typha addresses from the Kubernetes Service or an address override. |

Layers inside the syncer pipeline and the sync server.

| Building block | Code | Responsible for |
|---|---|---|
| Datastore syncer | `typha/pkg/daemon/daemon.go` (`addSyncerPipeline`) | Listing and watching the datastore for one syncer type, with no node filter. |
| Decoupler | `typha/pkg/calc/async_decoupler.go` (`SyncerCallbacksDecoupler`) | A channel hop that lets each pipeline stage run on its own goroutine. |
| `ValidationFilter` | `typha/pkg/calc/validation_filter.go` (`ValidationFilter`) | Validating each KVPair and turning an invalid value into a delete. |
| Node counter | `typha/pkg/calc/node_counter.go` (`NodeCounter`) | Counting Nodes in the Felix pipeline so the rebalancer knows the cluster size. |
| Snapshot cache | `typha/pkg/snapcache/cache.go` (`Cache`) | Holding serialized KVPairs and publishing Breadcrumbs. |
| Binary snapshot cache | `typha/pkg/syncserver/snap_precalc.go` (`SnapshotCache`) | Keeping one pre-encoded snapshot per syncer type and compression algorithm for new clients. |
| Connection | `typha/pkg/syncserver/sync_server.go` (`connection`) | One client: handshake, snapshot, delta loop, ping and pong, fall-behind check. |
| Connection governor | `typha/pkg/syncserver/sync_server.go` (`governNumberOfConnections`) | Dropping random connections while the server is above its connection limit. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Syncer type](../GLOSSARY.md#syncer-type)

**Syncer pipeline**:
The per-syncer-type chain inside Typha: datastore syncer, decoupler, `ValidationFilter`, decoupler, snapshot cache.
Code: `typha/pkg/daemon/daemon.go` (`syncerPipeline`).
_Avoid_: pipeline (on its own)

**Snapshot cache**:
The per-syncer-type store of serialized KVPairs, published as Breadcrumbs. The Go type is `snapcache.Cache`.
Code: `typha/pkg/snapcache/cache.go` (`Cache`).
_Avoid_: SnapshotCache (that is the binary snapshot cache's type name), cache (on its own)

**Binary snapshot cache**:
The sync server's store of binary snapshots, one per syncer type and compression algorithm. The Go type is `syncserver.SnapshotCache`.
Code: `typha/pkg/syncserver/snap_precalc.go` (`SnapshotCache`).
_Avoid_: SnapshotCache, snapshot cache (that is the Breadcrumb store)

**Binary snapshot**:
One Breadcrumb's KVPairs pre-encoded as a gob stream, optionally compressed, and ending in a decoder restart.
Code: `typha/pkg/syncserver/snap_precalc.go` (`SnapshotCache`).
_Avoid_: cached snapshot, snapshot (on its own)

**Breadcrumb**:
One immutable point-in-time snapshot of the snapshot cache, plus the deltas since the previous Breadcrumb and a link to the next.
Code: `typha/pkg/snapcache/cache.go` (`Breadcrumb`).
_Avoid_: crumb, snapshot (on its own)

**Handshake**:
The opening message exchange on a new connection, made up of the client's hello and the server's hello.
Code: `typha/pkg/syncserver/sync_server.go` (`doHandshake`), `typha/pkg/syncproto/sync_proto.go` (`MsgClientHello`, `MsgServerHello`).
_Avoid_: hello (that is only one message of the exchange)

**Decoder restart**:
The point in the stream where the encoding changes.
Code: `typha/pkg/syncproto/sync_proto.go` (`MsgDecoderRestart`).
_Avoid_: reset

**Modern policy keys**:
The client capability flag meaning the client keys policies by kind, namespace and name with no tier in the key.
Code: `typha/pkg/syncproto/sync_proto.go` (`SupportsModernPolicyKeys`).
_Avoid_: LegacyPolicyKey (that is the older form with a tier in the key)

**Serialized update**:
The wire form of one syncer update, with the key written as its default path and the value as JSON.
Code: `typha/pkg/syncproto/sync_proto.go` (`SerializedUpdate`).
_Avoid_: bare update (the in-process form is a KVPair plus an update type)

**Fall behind**:
A client falls behind when its current Breadcrumb is more than `MaxFallBehind` older than the latest one.
Code: `typha/pkg/syncserver/sync_server.go` (`MaxFallBehind`).
_Avoid_: lag (without the threshold)

**Fall-behind disconnect**:
The disconnect Typha applies to a client that fell behind. It is one kind of connection shedding.
Code: `typha/pkg/syncserver/sync_server.go` (`connection`).
_Avoid_: too far behind, lag (it has no threshold)

**`NewClientFallBehindGracePeriod`**:
The grace period during which a newly connected client is exempt from the fall-behind disconnect.
Code: `typha/pkg/syncserver/sync_server.go` (`NewClientFallBehindGracePeriod`).
_Avoid_: lag (it has no threshold)

**Connection shedding**:
Typha dropping client connections on purpose. A fall-behind disconnect is shedding too.
Code: `typha/pkg/syncserver/sync_server.go` (`governNumberOfConnections`).
_Avoid_: load balancing (the Service does that)

**Connection rebalancing**:
Connection shedding driven by the rebalancer.
Code: `typha/pkg/k8s/rebalance.go` (`CalculateMaxConnLimit`).
_Avoid_: load balancing

**Max connections**:
The per-Typha connection limit, counted separately for each syncer type.
Code: `typha/pkg/syncserver/sync_server.go` (`MaxConns`).
_Avoid_: MaxConns

**Graceful shutdown**:
Typha's orderly exit, in which it drops its client connections before the process ends.
Code: `typha/pkg/syncserver/sync_server.go` (`handleGracefulShutDown`).
_Avoid_: graceful restart (that is BIRD's)

**Syncer client**:
The client end of the Typha protocol, with the same callbacks interface as a local datastore syncer.
Code: `typha/pkg/syncclient/sync_client.go` (`SyncerClient`).
_Avoid_: Typha client (ambiguous with discovery)

**Typha discovery**:
Finding the addresses of the Typha instances a client can connect to.
Code: `typha/pkg/discovery/discovery.go` (`Discoverer`).
_Avoid_: rebalancer (that adjusts connection limits, not addresses)

**`ValidationFilter` (Typha)**:
The pipeline stage that validates each KVPair and replaces an invalid value with a delete. Felix's calculation graph has its own validation filter with the same name.
Code: `typha/pkg/calc/validation_filter.go` (`ValidationFilter`).
_Avoid_: validator (on its own)

**Decoupler**:
A pipeline stage that passes updates over a channel so the stage before it and the stage after it run on separate goroutines.
Code: `typha/pkg/calc/async_decoupler.go` (`SyncerCallbacksDecoupler`).
_Avoid_: dedupe buffer (that is a different type, used in Felix)
