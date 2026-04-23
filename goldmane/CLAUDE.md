# Goldmane

Goldmane is a flow aggregation service that provides a central, aggregated view of network flows in a Kubernetes cluster. It receives per-node flow data from Felix via gRPC, aggregates flows across nodes and time, and optionally emits them to an upstream HTTP endpoint. It also serves queries for the Whisker UI.

## Architecture

### gRPC Services (defined in `proto/api.proto`)

Goldmane exposes three gRPC services on a single TLS-enabled port (default 443, typically accessed via Kubernetes Service on port 7443):

- **FlowCollector** — receives streaming flow updates from Felix on each node (`Connect` RPC, bidirectional streaming). Deduplicates flows on reconnection.
- **Flows** — serves flow queries to consumers (Whisker UI, debugging tools). Supports `List` (paginated), `Stream` (live updates), and `FilterHints` (autocomplete-style filter discovery).
- **Statistics** — serves per-policy/per-rule statistics with optional time-series data.

### Core Components

| Package | Description |
|---|---|
| `cmd/` | Main entrypoint — calls `daemon.Run()` with env-based config |
| `cmd/stream/` | Debug CLI tool that connects to Goldmane and prints streamed flows |
| `cmd/flowgen/` | Test tool that generates fake flow data |
| `cmd/health/` | Health check binary |
| `pkg/daemon/` | Daemon setup — gRPC server, TLS, health, emitter, sink management |
| `pkg/goldmane/` | Core aggregation engine — single main loop serializing all operations (flow ingestion, rollover, queries, stream backfill, sink changes) |
| `pkg/storage/` | BucketRing (ring buffer of time-bucketed flow data), DiachronicFlow (per-flow-key time series), indices for sorting/filtering |
| `pkg/server/` | gRPC service implementations wrapping the Goldmane engine |
| `pkg/client/` | Go client wrappers for the gRPC services |
| `pkg/emitter/` | Pushes aggregated flows to an upstream HTTP endpoint via a rate-limited workqueue |
| `pkg/stream/` | Stream management for live flow subscriptions |
| `pkg/types/` | Internal flow types (minified from proto) and filter logic |
| `pkg/internal/` | Flow cache (deduplication) and file-watching utilities |
| `proto/` | Protobuf definitions and generated code |
| `fv/` | Functional verification tests (vanilla `go test`, not Ginkgo) |

### Data Flow

```
Felix (per-node) --gRPC--> FlowCollector --> Goldmane main loop --> BucketRing
                                                    |                    |
                                                    |                    +--> Flows/Statistics gRPC queries
                                                    |                    +--> Stream subscriptions
                                                    |
                                                    +--> (on rollover) --> Emitter --> upstream HTTP endpoint
```

### Key Concepts

- **BucketRing**: Ring buffer of `AggregationBucket`s. Each bucket covers a fixed time interval (default 15s). On rollover, the oldest bucket is recycled. Keeps ~1hr of history (242 buckets).
- **DiachronicFlow**: Tracks a single flow key's statistics across all time buckets.
- **Rollover**: Every `AggregationWindow` (15s), the main loop advances the ring. On rollover, old buckets are emitted to the sink (if configured) and streams receive updates.
- **Sink**: An optional downstream consumer of aggregated flows (the Emitter). Can be enabled/disabled at runtime via a file watch (`FileConfigPath`).
- **Emitter**: Batches aggregated flows and pushes them to an upstream endpoint over HTTPS with mTLS. Tracks progress in a ConfigMap (`flow-emitter-state` in `calico-system`).

### Configuration

All config via environment variables (see `pkg/daemon/daemon.go` `Config` struct):

| Env Var | Default | Description |
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

## Build & Test

```bash
# Build binaries
make build

# Build Docker image
make image

# Run unit tests
make ut

# Run unit tests directly (faster iteration, no Docker)
go test ./...

# Run benchmarks
make benchmark

# Regenerate protobuf
make protobuf

# Regenerate mocks
make gen-mocks
```

FV tests are in `fv/` and use vanilla `go test` (not Ginkgo). They spin up a real Goldmane daemon with TLS and test the full gRPC flow.

## Debugging on a Running Cluster

### Fetching Credentials

Goldmane requires mTLS. Fetch credentials from a running cluster:

```bash
# Client cert/key (using calico/node credentials)
kubectl get secret -n calico-system node-certs --template='{{index .data "tls.key"}}' | base64 -d > tls.key
kubectl get secret -n calico-system node-certs --template='{{index .data "tls.crt"}}' | base64 -d > tls.crt

# CA cert (from Goldmane's own keypair)
kubectl get secret -n calico-system goldmane-key-pair --template='{{index .data "tls.crt"}}' | base64 -d > ca.crt
```

### Port Forwarding

```bash
kubectl port-forward -n calico-system svc/goldmane 7443:7443
```

### Using grpcurl

Goldmane does not support gRPC reflection, so you must pass the proto file with `-import-path` and `-proto`. You also need `-authority` to override the TLS server name (the cert is issued for `goldmane.calico-system.svc`, not `localhost`).

Install grpcurl if needed: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`

```bash
GRPC="grpcurl -cert tls.crt -key tls.key -cacert ca.crt -authority goldmane.calico-system.svc -import-path /path/to/calico/goldmane/proto -proto api.proto"

# List services
$GRPC localhost:7443 list

# List flows (last 5 minutes)
$GRPC -d '{"start_time_gte": -300, "start_time_lt": 0}' localhost:7443 goldmane.Flows/List

# Stream live flows (start_time_gte of 0 means "now", negative means relative seconds)
$GRPC -d '{"start_time_gte": -60}' localhost:7443 goldmane.Flows/Stream

# Get filter hints (e.g., available destination names)
$GRPC -d '{"type": "FilterTypeDestName"}' localhost:7443 goldmane.Flows/FilterHints

# Query statistics (packet counts, time-series)
$GRPC -d '{"start_time_gte": -300, "start_time_lt": 0, "type": "PacketCount", "time_series": true}' localhost:7443 goldmane.Statistics/List
```

### Using the Stream Debug Tool

Build and use the included stream client (`cmd/stream/`):

```bash
make build
./bin/stream-$(ARCH) -start=-300  # stream flows starting from 5 min ago
```

This requires `tls.crt`, `tls.key`, and `ca.crt` in the current directory and expects to connect to `goldmane:7443` (add a `/etc/hosts` entry or use the port-forward).

### Checking Goldmane Logs

```bash
kubectl logs -n calico-system -l k8s-app=goldmane -f
```

### Checking Felix Flow Logs (Ingestion Side)

Felix is the source of flow data sent to Goldmane. Each calico-node pod runs a Felix instance that aggregates per-connection flow data and streams it to Goldmane via gRPC. Felix flow log messages are at debug level by default — look for `goldmane` or `flow` references.

```bash
# Check Felix logs across all nodes
kubectl logs -n calico-system -l k8s-app=calico-node -c calico-node --tail=50

# Filter for flow/goldmane-related messages
kubectl logs -n calico-system -l k8s-app=calico-node -c calico-node | grep -iE 'goldmane|flow'

# Check a specific node's Felix logs (useful for debugging per-node ingestion issues)
kubectl logs -n calico-system <calico-node-pod> -c calico-node | grep -iE 'goldmane|flow'
```

Key Felix log messages to look for:
- `Creating Flow Logs GoldmaneReporter` — Felix is initializing its Goldmane client (at startup)
- `Creating goldmane Aggregator for allowed/denied` — Felix flow aggregation is being configured
- `Dispatching flow logs to goldmane` — Felix is sending flows (debug level)

On the Goldmane side, successful client connections appear as:
```
Connection from client who=<node-IP>:<port>
```

If flows aren't appearing in Goldmane, check:
1. Felix logs for connection errors to Goldmane
2. Goldmane logs for `Connection from client` messages (should see one per node)
3. The `goldmane_collector_num_clients` Prometheus metric (should match node count)
4. The `goldmane_collector_received_flows` metric (should be incrementing per source)

### Checking Emitter State

The emitter is only active when `PUSH_URL` is configured and the sink is enabled (via `FILE_CONFIG_PATH`). This is typically only in Calico Enterprise / Calico Cloud installations. In a default OSS installation, the emitter is not configured. When active, it tracks progress in a ConfigMap:

```bash
kubectl get configmap -n calico-system flow-emitter-state -o yaml
```

### Enabling Prometheus Metrics

`PROMETHEUS_PORT` defaults to 0 (disabled). You can enable it via the Goldmane operator CR:

```bash
# Enable metrics on port 9081
kubectl patch goldmane default --type=merge -p '{"spec":{"metricsPort": 9081}}'

# Wait for the rollout
kubectl rollout status deployment/goldmane -n calico-system
```

This sets `PROMETHEUS_PORT` on the container, creates a headless `goldmane-metrics` Service with `prometheus.io/scrape` annotations, and opens the metrics port in the NetworkPolicy.

To scrape metrics locally:

```bash
# Port-forward to the metrics service
kubectl port-forward -n calico-system svc/goldmane-metrics 9081:9081

# Fetch metrics
curl -s http://localhost:9081/metrics | grep '^goldmane_'
```

To disable metrics:

```bash
kubectl patch goldmane default --type=json -p '[{"op": "remove", "path": "/spec/metricsPort"}]'
```

### Prometheus Metrics Reference

Useful Goldmane-specific metrics:

**Aggregator metrics** (`goldmane_aggr_*`):
- `goldmane_aggr_received_flows_total` — total flows ingested into the aggregator
- `goldmane_aggr_dropped_flows_total` — flows dropped due to full buffer
- `goldmane_aggr_num_unique_flows` — current number of unique flow keys
- `goldmane_aggr_flow_index_buffer_size` — current ingestion buffer depth
- `goldmane_aggr_flow_index_batch_size` — number of flows processed per batch
- `goldmane_aggr_flow_index_latency_ms` — time to index a single flow
- `goldmane_aggr_rollover_duration_ms` — time spent performing bucket rollover
- `goldmane_aggr_rollover_latency_ms` — time between rollovers (should be ~15s)
- `goldmane_aggr_backfill_latency_ms` — time to backfill a new stream with historical data

**Collector metrics** (`goldmane_collector_*`):
- `goldmane_collector_received_flows` (label: `source`) — flows received per Felix node
- `goldmane_collector_flow_process_latency` (label: `source`) — ingestion latency histogram per node
- `goldmane_collector_num_clients` — number of connected Felix clients (should match node count)

**Stream metrics**:
- `goldmane_num_streams` — number of active gRPC stream subscriptions
