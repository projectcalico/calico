<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# The Syncer API

The Syncer API is Calico's "download and watch" abstraction over
the backend datastore. A syncer connects to the datastore
(Kubernetes API server or etcd), downloads the current state of a
set of resources, and then watches for changes — delivering both
phases to its consumer through one callback interface. It is
deliberately lowest-common-denominator: the same consumer code
works against either backend, so its guarantees are only those
every backend can honour.

The API is cross-component: it is defined in
`libcalico-go/lib/backend/api`, implemented by the syncers in
`libcalico-go/lib/backend/syncersv1/`, consumed by Felix's
calculation graph, confd, the `node` helpers, kube-controllers and
the apiserver, and extended
over the network by Typha. This doc is the authoritative
statement of the API's contract; the consumers document their own
side:

- Felix's calc graph:
  [`felix/design/calc-graph.md`](../../felix/design/calc-graph.md)
  ("The upstream (syncer) contract").
- Typha (the remote fan-out of this API):
  [`typha/DESIGN.md`](../../typha/DESIGN.md).

## The API

Defined in `libcalico-go/lib/backend/api/api.go`:

```go
type Syncer interface {
	Start()
	Stop()
}

type SyncerCallbacks interface {
	OnStatusUpdated(status SyncStatus)
	OnUpdates(updates []Update)
}
```

`OnUpdates` delivers typed key/value pairs (`Update` embeds
`model.KVPair` plus an `UpdateType`). Keys are drawn from
`libcalico-go/lib/backend/model`; a **`nil` value means the key
does not exist** (deleted, or its value failed to parse).

`OnStatusUpdated` reports the state of the stream as a whole —
whether the consumer can trust its local picture of the
datastore. `SyncStatus` values:

- `WaitForDatastore` — not yet connected (or datastore not ready).
- `ResyncInProgress` — the syncer is (re)downloading existing
  state; updates for all existing keys are being sent, interleaved
  with any concurrent changes.
- `InSync` — all existing keys have been sent; the consumer now
  has the full picture.

The status is not monotonic: after `InSync` it can drop back to
`ResyncInProgress` (a full resync, e.g. an expired watch) or to
`WaitForDatastore` (a prolonged disconnect, or a Typha reconnect).
A resource type whose API isn't installed counts as empty and
`InSync`.

Optional extensions, detected by type assertion on the callbacks:
`SyncerParseFailCallbacks` and `SyncFailCallbacks` (in
`api.go`), and Typha's `syncclient.RestartAwareCallbacks`.

## The consumer algorithm

The API is eventually consistent. A consumer that applies the
following algorithm will converge on the current state of the
datastore:

1. Start with an empty key/value map, marked "not complete".
2. On `OnUpdates`, apply each update to the map: non-nil value →
   store it; nil value → delete the key.
3. On `OnStatusUpdated(InSync)`, mark the map "complete". It is
   now a full snapshot of the datastore at some (hopefully
   recent) point in time.
4. Keep applying updates. After `InSync`, act on each update
   immediately: the map plus the update *is* the current state.
5. A later `ResyncInProgress` or `WaitForDatastore` means the
   syncer lost confidence in the stream; the consumer may want to
   stop trusting its map until the next `InSync`.

Tracking completeness matters because a consumer shouldn't do
anything disruptive on a partial picture — Felix, for example,
must not program policy until it has seen *all* the policy.

## The contract

The **only** real guarantee is eventual convergence to the latest
value of each key (supported datastores make writes durable, so,
connectivity permitting, the latest value will eventually be
delivered). Everything else is fair game. For a resource that
truly went `Created → A → B → C`, a consumer might observe any of:

- `A → B → C`
- `A → C` — `B` coalesced away
- `C` — `A` and `B` coalesced away
- `A → C → B → C` — reached `C`, then a resync hit a stale
  replica (back to `B`), then caught up
- `C → Deleted → A → B → C` — resync hit a replica so stale the
  resource didn't exist there yet, giving a **spurious `Deleted`**

So a consumer must not assume ordering across keys, monotonic
versions, that it sees every transition, or that a `Deleted` is
final — the same resource can be deleted and later re-created.
Reasoning about each event on its own, against prior knowledge of
*that one key*, handles all of these; assuming values only move
forward does not.

Two further properties:

- **Recursive deletes are expanded.** Deleting a subtree produces
  one deletion update per leaf key (`OnUpdates` doc comment).
- **`Stop()` emits deletions** for every key the syncer had
  reported, returning the consumer to an empty state.

### The update-type side channel

Each `Update` carries `UpdateType`
(`UpdateTypeKVNew`/`KVUpdated`/`KVDeleted`/`KVUnknown`). Its
purpose is stats-style bookkeeping without retaining objects
(e.g. Felix's `calc/stats_collector.go`). **Don't drive
correctness from it** — decide existence from nil/non-nil, not
the update type. `UpdateTypeKVNew/Updated` can even carry a `nil`
value (failed validation in Typha or the consumer), so the type
may disagree with the value. Intermediaries that coalesce updates
must rewrite the type so that the *sequence* of types a consumer
sees remains consistent (a consumer that has seen `New` for a key
must next see `Updated` or `Deleted`, never another `New`) — the
`dedupebuffer` rewrites per key against what it has delivered,
and Typha's cache sends snapshot entries as `New` (see
[`typha/design/server.md`](../../typha/design/server.md)).

## Implementations

The generic machinery is `libcalico-go/lib/backend/watchersyncer`
— it runs one `watchercache` per resource type (list + watch
against the backend client, in the style of a Kubernetes
reflector) and merges the streams, computing the overall
`SyncStatus`. The `watchercache`'s per-key revision map is where
`UpdateType`s are minted: `KVNew` vs `KVUpdated` by whether the
key was already announced, same-revision events swallowed, and
`KVDeleted` only for previously-announced keys, so the
`watchersyncer` never emits a deletion without an earlier `KVNew`
(intermediaries may still forward deletions for keys whose
earlier update they nil'd). The per-purpose syncers in
`libcalico-go/lib/backend/syncersv1/` compose it with a resource
list and, per resource, an optional `updateprocessor` that
converts the v3 resource into v1 model keys. Unprocessed
resources are delivered as v3 `ResourceKey`s, so consumers see a
mix of both:

| Syncer | Consumer |
|---|---|
| `felixsyncer` | Felix's calc graph |
| `bgpsyncer` | confd (BIRD config generation) |
| `tunnelipsyncer` | `node` tunnel-IP allocation |
| `nodestatussyncer` | `node` status reporter |

These four correspond one-to-one with Typha's `SyncerType`s
(`typha/pkg/syncproto`): Typha runs each syncer once and fans it
out, so consumers get the same streams without the datastore
seeing one watcher per node. confd and the `node` helpers use
`typha/pkg/syncclientutils.MustStartSyncerClientIfTyphaConfigured`
to connect via Typha when configured and run the syncer
in-process otherwise; Felix wires the Typha client itself. The
callbacks see the same API either way.

kube-controllers (`controllers/utils.DataFeed`) and the apiserver
also use `watchersyncer` directly, with their own resource lists,
never via Typha.

`libcalico-go/lib/backend/syncersv1/dedupebuffer` is a
`SyncerCallbacks` adaptor that sits between a syncer (or Typha
client) and a slow consumer: it coalesces repeated updates to the
same key while queueing, and it absorbs a Typha reconnection
(`OnTyphaConnectionRestarted`): the new snapshot passes through
(already-delivered keys as `KVUpdated`), and at `InSync` it
synthesizes deletions for delivered keys the new snapshot lacked.
The consumer sees the status drop back, but no spurious
delete/re-create.

## Review notes

- A consumer (or intermediary) that decides *existence* from
  `UpdateType` rather than nil/non-nil is suspect; stats-style
  bookkeeping is the only legitimate use of the type.
- A consumer that assumes monotonic versions, cross-key ordering,
  or that it sees every intermediate update is wrong — coalescing
  and resync-reversion break all three.
- An intermediary that filters or coalesces the stream must
  preserve the contract as seen by its downstream: deletions for
  keys it reported, a consistent `UpdateType` sequence, and
  `InSync` only once the downstream really has the full picture.
  Claiming `InSync` early triggers disruptive action (dataplane
  programming) on a partial picture; delaying it is safe.
- A change to the API's semantics (new `SyncStatus`, new
  guarantee, new optional callback interface) affects every
  consumer listed above *and* the Typha protocol — check each.
