<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Goldmane — Design

Goldmane is a flow aggregation service that provides a central,
aggregated view of network flows in a Kubernetes cluster. It
receives per-node flow data from Felix via gRPC, aggregates flows
across nodes and time, and optionally emits them to an upstream
HTTP endpoint. It also serves queries for the Whisker UI.

Operational guidance (build, test, debug recipes) lives in
[`goldmane/CLAUDE.md`](./CLAUDE.md). This document is for
architecture, invariants, and the daemon's external surface.

## gRPC services

Defined in `proto/api.proto`. Goldmane exposes three services on a
single TLS-enabled port (default `443`, typically accessed via
Kubernetes Service on port `7443`):

- **`FlowCollector`** — receives streaming flow updates from Felix
  on each node (`Connect` RPC, bidirectional streaming).
  Deduplicates flows on reconnection.
- **`Flows`** — serves flow queries to consumers (Whisker UI,
  debugging tools). Supports `List` (paginated), `Stream` (live
  updates), and `FilterHints` (autocomplete-style filter
  discovery).
- **`Statistics`** — serves per-policy/per-rule statistics with
  optional time-series data.

## Core components

| Package | Description |
|---|---|
| `cmd/` | Main entrypoint — calls `daemon.Run()` with env-based config |
| `cmd/stream/` | Debug CLI tool that connects to Goldmane and prints streamed flows |
| `cmd/flowgen/` | Test tool that generates fake flow data |
| `cmd/health/` | Health check binary |
| `pkg/daemon/` | Daemon setup — gRPC server, TLS, health, emitter, sink management |
| `pkg/goldmane/` | Core aggregation engine — single main loop serializing all operations (flow ingestion, rollover, queries, stream backfill, sink changes) |
| `pkg/storage/` | `BucketRing` (ring buffer of time-bucketed flow data), `DiachronicFlow` (per-flow-key time series), indices for sorting/filtering |
| `pkg/server/` | gRPC service implementations wrapping the Goldmane engine |
| `pkg/client/` | Go client wrappers for the gRPC services |
| `pkg/emitter/` | Pushes aggregated flows to an upstream HTTP endpoint via a rate-limited workqueue |
| `pkg/stream/` | Stream management for live flow subscriptions |
| `pkg/types/` | Internal flow types (minified from proto) and filter logic |
| `pkg/internal/` | Flow cache (deduplication) and file-watching utilities |
| `proto/` | Protobuf definitions and generated code |
| `fv/` | Functional verification tests (vanilla `go test`, not Ginkgo) |

## Data flow

```
Felix (per-node) --gRPC--> FlowCollector --> Goldmane main loop --> BucketRing
                                                    |                    |
                                                    |                    +--> Flows/Statistics gRPC queries
                                                    |                    +--> Stream subscriptions
                                                    |
                                                    +--> (on rollover) --> Emitter --> upstream HTTP endpoint
```

## Key concepts

- **`BucketRing`** — ring buffer of `AggregationBucket`s. Each
  bucket covers a fixed time interval (default 15 s). On
  rollover, the oldest bucket is recycled. Keeps ~1 hour of
  history (242 buckets).
- **`DiachronicFlow`** — tracks a single flow key's statistics
  across all time buckets.
- **Rollover** — every `AggregationWindow` (15 s), the main loop
  advances the ring. On rollover, old buckets are emitted to the
  sink (if configured) and streams receive updates.
- **Sink** — optional downstream consumer of aggregated flows (the
  emitter). Can be enabled/disabled at runtime via a file watch
  (`FileConfigPath`).
- **Emitter** — batches aggregated flows and pushes them to an
  upstream endpoint over HTTPS with mTLS. Tracks progress in a
  `ConfigMap` (`flow-emitter-state` in `calico-system`).

### Review notes

- A change to any of the five concepts above — bucket layout,
  rollover cadence, emit semantics, sink reload protocol — is a
  protocol-level change. Callers (Felix's flow reporter, Whisker,
  the emitter's upstream consumer) will notice. Update this
  document and bump proto compatibility if the wire format
  changes.
- The main loop serialises all operations. Adding a new operation
  that must not block the loop (e.g. a long-running query) needs
  an explicit design — do not just `go` it.
- A change to `BucketRing`'s sizing or `AggregationWindow`
  default affects memory footprint; benchmark before changing.

## Configuration (env vars)

All config via environment variables (see `pkg/daemon/daemon.go`
`Config` struct). Adding a new env var is a design change: it
extends the daemon's external contract.

| Env var | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `info` | Log level |
| `PORT` | `443` | gRPC listen port |
| `PUSH_URL` | (empty) | HTTP endpoint for flow emission |
| `AGGREGATION_WINDOW` | `15s` | Bucket duration |
| `EMIT_AFTER_SECONDS` | `30` | Delay before emitting (completeness vs latency) |
| `EMITTER_AGGREGATION_WINDOW` | `5m` | Time window aggregated per emission |
| `SERVER_CERT_PATH` / `SERVER_KEY_PATH` | (empty) | Server TLS for gRPC |
| `CLIENT_CERT_PATH` / `CLIENT_KEY_PATH` / `CA_CERT_PATH` | (empty) | Client mTLS for upstream HTTP endpoint |
| `HEALTH_PORT` | `8080` | Health check port |
| `PROFILE_PORT` | `0` (disabled) | pprof port |
| `PROMETHEUS_PORT` | `0` (disabled) | Prometheus metrics port |

### Review notes

- A new env var needs a default that preserves existing
  behaviour (opt-in or no-op by default).
- Changing a default for an existing var is an observable
  behaviour change — treat it as a semver-minor at least.
- TLS-related vars (`*_CERT_PATH` / `*_KEY_PATH`) interact with
  the operator's secret mounts; coordinate with the operator
  CR when changing defaults or adding new cert inputs.

## Prometheus metrics

Goldmane's observable surface. Adding/renaming/removing a metric
is a contract change for dashboards and alerting; record it here.

**Aggregator metrics** (`goldmane_aggr_*`):
- `goldmane_aggr_received_flows_total` — total flows ingested
  into the aggregator.
- `goldmane_aggr_dropped_flows_total` — flows dropped due to
  full buffer.
- `goldmane_aggr_num_unique_flows` — current number of unique
  flow keys.
- `goldmane_aggr_flow_index_buffer_size` — current ingestion
  buffer depth.
- `goldmane_aggr_flow_index_batch_size` — number of flows
  processed per batch.
- `goldmane_aggr_flow_index_latency_ms` — time to index a single
  flow.
- `goldmane_aggr_rollover_duration_ms` — time spent performing
  bucket rollover.
- `goldmane_aggr_rollover_latency_ms` — time between rollovers
  (should be ~15 s).
- `goldmane_aggr_backfill_latency_ms` — time to backfill a new
  stream with historical data.

**Collector metrics** (`goldmane_collector_*`):
- `goldmane_collector_received_flows` (label: `source`) — flows
  received per Felix node.
- `goldmane_collector_flow_process_latency` (label: `source`) —
  ingestion latency histogram per node.
- `goldmane_collector_num_clients` — number of connected Felix
  clients (should match node count).

**Stream metrics:**
- `goldmane_num_streams` — number of active gRPC stream
  subscriptions.

### Review notes

- A new metric needs a name in the documented namespace
  (`goldmane_*`, `goldmane_aggr_*`, or `goldmane_collector_*`)
  and an entry in this table.
- Dropping a metric is a dashboard-breaking change — record the
  reason and migration path in the removal commit.
- Label cardinality matters: per-node labels (`source`) are fine
  up to cluster size; per-flow-key labels would be unbounded and
  are forbidden.

## Cross-cutting review notes

- **Keep this document in sync with the code.** A change to the
  gRPC services, core components, key concepts, config surface,
  or Prometheus metrics must update the relevant section in the
  same PR. Exemptions: (a) a bug fix that restores behaviour
  this doc already describes, (b) a mechanical refactor with no
  observable change, (c) comment / log-message edits, (d)
  dependency bumps. If in doubt, update the doc.
- Operational recipes (build, test, debug) do not belong here —
  they live in [`goldmane/CLAUDE.md`](./CLAUDE.md).
