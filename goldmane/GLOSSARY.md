# Goldmane glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `goldmane/`, which is also a library: Felix imports its client, types and server packages.

## Building blocks

The top layer of the Goldmane daemon.

| Building block | Code | Responsible for |
|---|---|---|
| Daemon | `goldmane/pkg/daemon/daemon.go` (`Run`) | Wires the gRPC server, TLS, health, the emitter and the sink manager from environment variables. |
| Goldmane engine | `goldmane/pkg/goldmane/goldmane.go` (`Goldmane`) | The main loop: one goroutine that serializes flow intake, rollover, queries, stream registration and sink changes. |
| Bucket ring | `goldmane/pkg/storage/bucket_ring.go` (`BucketRing`) | The ring of aggregation buckets plus the flow-key map. Does rollover, emission batching and per-reporter-address dedup. |
| Stream manager | `goldmane/pkg/stream/stream_manager.go` (`StreamManager`) | Registry of live `Flows.Stream` subscribers, fed on rollover. |
| Emitter | `goldmane/pkg/emitter/emitter.go` (`Emitter`) | Pushes flow collections as NDJSON over mTLS through a rate-limited workqueue. |
| Sink manager | `goldmane/pkg/daemon/config.go` (`sinkManager`) | Watches the file config and attaches or detaches the emitter as the sink. |
| Flow collector service | `goldmane/pkg/server/flow_collector_service.go` (`flowCollectorService`) | Handles `FlowCollector.Connect`: tags each flow with the reporter address and acknowledges with a `FlowReceipt`. |
| Flow client | `goldmane/pkg/client/client.go` (`FlowClient`) | The client library Felix runs. Streams flows to Goldmane and replays its cache after a reconnect. |

The storage layer, one layer down.

| Building block | Code | Responsible for |
|---|---|---|
| Aggregation bucket | `goldmane/pkg/storage/bucket.go` (`AggregationBucket`) | The flows and policy statistics for one aggregation window, plus its emission claims. |
| Diachronic Flow | `goldmane/pkg/storage/diachronic_flow.go` (`DiachronicFlow`) | Per-flow-key statistics with one window per bucket, plus the source and destination IP sets. |
| Index | `goldmane/pkg/storage/index.go` (`Index`) | Sorted lookup by name or namespace for `List` queries. |
| Ring index | `goldmane/pkg/storage/ring_index.go` (`RingIndex`) | Time-ordered lookup for `List` queries. |
| Statistics index | `goldmane/pkg/storage/stats.go` (`statisticsIndex`) | Per-policy and per-rule counters behind the `Statistics` service. |
| Deferred flow builder | `goldmane/pkg/storage/deferred_builder.go` (`DeferredFlowBuilder`) | Builds a protobuf `Flow` only when it matches a stream's filter. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [End-of-tier hit](../GLOSSARY.md#end-of-tier-hit)
- [Filter hints](../GLOSSARY.md#filter-hints)
- [Flow endpoint type](../GLOSSARY.md#flow-endpoint-type)
- [Flow key](../GLOSSARY.md#flow-key)
- [Goldmane Flow](../GLOSSARY.md#goldmane-flow)
- [Pending policy trace](../GLOSSARY.md#pending-policy-trace)
- [Query filter](../GLOSSARY.md#query-filter)

### Flow data

#### Diachronic Flow
All of one flow key's time-windowed statistics and IP sets across the whole bucket ring.
Code: `goldmane/pkg/storage/diachronic_flow.go` (`DiachronicFlow`).
_Avoid_: flow, unqualified

#### Window
One Diachronic Flow's counters and labels for a single bucket's time range.
Code: `goldmane/pkg/storage/diachronic_flow.go` (`Window`).
_Avoid_: bucket (that is the ring slot)

#### Flow IP set
The best-effort set of distinct source or destination IP addresses on a Goldmane Flow.
Code: `goldmane/pkg/storage/diachronic_flow.go` (`MaxIPsPerFlow`).
_Avoid_: IP set (that is the dataplane object)

#### Reporter
Which end of the connection measured the flow, `src` or `dst`.
Code: `goldmane/proto/api.proto` (`Reporter`).
_Avoid_: reporter for the reporting node (see reporter address)

#### Reporter address
The IP address of the Felix connection that reported a flow, without the port. It is an IP address, not a node name.
Code: `goldmane/pkg/server/flow_collector_service.go` (`flowCollectorService`).
_Avoid_: node scope, scope, who, client

#### Policy trace
The ordered policy rules that acted on a flow, held as an enforced list and a pending list, each hit carrying tier, kind, index and action.
Code: `goldmane/proto/api.proto` (`PolicyTrace`).
_Avoid_: policy hits, as a name for the whole list

#### Policy trace cache
A two-generation cache that decodes interned policy-trace strings into their hits.
Code: `goldmane/pkg/types/policy_trace_cache.go` (`policyTraceCache`).
_Avoid_: nothing known

#### Flow conversion contract
The mapping from a Felix flow log to a Goldmane Flow.
Code: `felix/collector/goldmane/client.go` (`ConvertFlowlogToGoldmane`).
_Avoid_: nothing known

### Aggregation and storage

#### Aggregation window
The duration one aggregation bucket covers.
Code: `goldmane/pkg/daemon/daemon.go` (`AggregationWindow`).
_Avoid_: flush interval (that is Felix's)

#### Aggregation bucket
One slot of the bucket ring, holding the flows seen during one aggregation window.
Code: `goldmane/pkg/storage/bucket.go` (`AggregationBucket`).
_Avoid_: window (that is a Diachronic Flow's counters for the bucket)

#### Bucket ring
The fixed ring of aggregation buckets that holds Goldmane's recent flows, in memory only.
Code: `goldmane/pkg/storage/bucket_ring.go` (`BucketRing`).
_Avoid_: storage, ring buffer

#### Rollover
Advancing the ring head by one bucket.
Code: `goldmane/pkg/storage/bucket_ring.go` (`Rollover`).
_Avoid_: flush

#### Goldmane engine
The `Goldmane` struct and its main loop, which takes in flows, aggregates them into buckets and emits them to the sink. The health name `aggregator` and the `goldmane_aggr_*` metrics refer to it, and Felix's `flowlog.Aggregator` is a different thing.
Code: `goldmane/pkg/goldmane/goldmane.go` (`Goldmane`).
_Avoid_: the aggregator

#### Flow ingestion
The engine's inbound path for flows from reporters.
Code: `goldmane/pkg/server/flow_collector_service.go` (`Sink`).
_Avoid_: sink (that is the emission output)

#### Backfill
Sending a new stream the ring's history from its start time.
Code: `goldmane/pkg/storage/bucket_ring.go` (`Backfill`).
_Avoid_: nothing known

### Reconnect replay and dedup

#### Reconnect replay
A Felix flow client re-sending its cached flows after it reconnects.
Code: `goldmane/pkg/client/client.go` (`FlowClient`).
_Avoid_: resync

#### Replay cache
The client-side cache of recently sent flows.
Code: `goldmane/pkg/internal/flowcache/timed_cache.go` (`ExpiringFlowCache`).
_Avoid_: flow cache, unqualified

#### Emission claim
A per-bucket record of a flow's ID, start, end and reporter address.
Code: `goldmane/pkg/storage/bucket.go` (`emissionKey`).
_Avoid_: claim, unqualified (IPAM also has block claims)

#### Dedup window
How many buckets back from the ring head keep their emission claims.
Code: `goldmane/pkg/storage/bucket_ring.go` (`dedupWindowBuckets`).
_Avoid_: replay horizon

### Emitting

#### Emit
Goldmane handing aggregated flows to its sink. A Felix sending a flow to Goldmane is a report, not an emit.
Code: `goldmane/pkg/storage/bucket_ring.go` (`EmitFlowCollections`).
_Avoid_: push, publish

#### Sink
The optional downstream that receives flow collections. In practice it is the emitter.
Code: `goldmane/pkg/storage/sink.go` (`Sink`).
_Avoid_: sink for the flow intake

#### Emitter
The sink that POSTs NDJSON flow batches to an external endpoint over mTLS.
Code: `goldmane/pkg/emitter/emitter.go` (`Emitter`).
_Avoid_: push, publish

#### Flow collection
A batch of Goldmane Flows aggregated over the emission window and handed to the sink as one unit.
Code: `goldmane/pkg/storage/utils.go` (`FlowCollection`).
_Avoid_: emitted flows, aggregated flow for emission

#### Emit delay
How many buckets behind the ring head a bucket must be before it can be emitted.
Code: `goldmane/pkg/daemon/daemon.go` (`EmitAfterSeconds`).
_Avoid_: push index, settling time

#### Emission window
How many buckets are merged into one flow collection.
Code: `goldmane/pkg/daemon/daemon.go` (`EmitterAggregationWindow`).
_Avoid_: buckets to aggregate, aggregation window

#### Emitter state
The ConfigMap `calico-system/flow-emitter-state`, which holds the end time of the latest emitted bucket.
Code: `goldmane/pkg/emitter/emitter.go` (`latestTimestamp`).
_Avoid_: latestTimestamp

#### File config
The JSON file with an `emitFlows` field that enables or disables the sink.
Code: `goldmane/pkg/daemon/config.go` (`goldmaneFileConfig`).
_Avoid_: goldmaneFileConfig
