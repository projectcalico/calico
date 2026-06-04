# Goldmane — Operational Guide

This file is operational guidance for agents working in Goldmane:
how to build, run tests, debug a running instance, and use
Goldmane-specific tooling.

For architecture, gRPC services, data flow, key concepts,
configuration surface, and Prometheus metric reference, see
[`goldmane/DESIGN.md`](./DESIGN.md).

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

FV tests are in `fv/` and use vanilla `go test` (not Ginkgo). They
spin up a real Goldmane daemon with TLS and test the full gRPC
flow.

## Debugging on a Running Cluster

### Fetching credentials

Goldmane requires mTLS. Fetch credentials from a running cluster:

```bash
# Client cert/key (using calico/node credentials)
kubectl get secret -n calico-system node-certs --template='{{index .data "tls.key"}}' | base64 -d > tls.key
kubectl get secret -n calico-system node-certs --template='{{index .data "tls.crt"}}' | base64 -d > tls.crt

# CA cert (from Goldmane's own keypair)
kubectl get secret -n calico-system goldmane-key-pair --template='{{index .data "tls.crt"}}' | base64 -d > ca.crt
```

### Port forwarding

```bash
kubectl port-forward -n calico-system svc/goldmane 7443:7443
```

### Using grpcurl

Goldmane does not support gRPC reflection, so you must pass the
proto file with `-import-path` and `-proto`. You also need
`-authority` to override the TLS server name (the cert is issued
for `goldmane.calico-system.svc`, not `localhost`).

Install grpcurl if needed:
`go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`

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

### Using the stream debug tool

Build and use the included stream client (`cmd/stream/`):

```bash
make build
./bin/stream-$(ARCH) -start=-300  # stream flows starting from 5 min ago
```

This requires `tls.crt`, `tls.key`, and `ca.crt` in the current
directory and expects to connect to `goldmane:7443` (add a
`/etc/hosts` entry or use the port-forward).

### Checking Goldmane logs

```bash
kubectl logs -n calico-system -l k8s-app=goldmane -f
```

### Checking Felix flow logs (ingestion side)

Felix is the source of flow data sent to Goldmane. Each
`calico-node` pod runs a Felix instance that aggregates
per-connection flow data and streams it to Goldmane via gRPC.
Felix flow log messages are at debug level by default — look for
`goldmane` or `flow` references.

```bash
# Check Felix logs across all nodes
kubectl logs -n calico-system -l k8s-app=calico-node -c calico-node --tail=50

# Filter for flow/goldmane-related messages
kubectl logs -n calico-system -l k8s-app=calico-node -c calico-node | grep -iE 'goldmane|flow'

# Check a specific node's Felix logs (useful for debugging per-node ingestion issues)
kubectl logs -n calico-system <calico-node-pod> -c calico-node | grep -iE 'goldmane|flow'
```

Key Felix log messages to look for:

- `Creating Flow Logs GoldmaneReporter` — Felix is initialising
  its Goldmane client (at startup).
- `Creating goldmane Aggregator for allowed/denied` — Felix flow
  aggregation is being configured.
- `Dispatching flow logs to goldmane` — Felix is sending flows
  (debug level).

On the Goldmane side, successful client connections appear as:

```
Connection from client who=<node-IP>:<port>
```

If flows aren't appearing in Goldmane, check:

1. Felix logs for connection errors to Goldmane.
2. Goldmane logs for `Connection from client` messages (should
   see one per node).
3. The `goldmane_collector_num_clients` Prometheus metric (should
   match node count).
4. The `goldmane_collector_received_flows` metric (should be
   incrementing per source).

### Checking emitter state

The emitter is only active when `PUSH_URL` is configured and the
sink is enabled (via `FILE_CONFIG_PATH`). This is typically only
in Calico Enterprise / Calico Cloud installations. In a default
OSS installation, the emitter is not configured. When active, it
tracks progress in a ConfigMap:

```bash
kubectl get configmap -n calico-system flow-emitter-state -o yaml
```

### Enabling Prometheus metrics

`PROMETHEUS_PORT` defaults to `0` (disabled). Enable it via the
Goldmane operator CR:

```bash
# Enable metrics on port 9081
kubectl patch goldmane default --type=merge -p '{"spec":{"metricsPort": 9081}}'

# Wait for the rollout
kubectl rollout status deployment/goldmane -n calico-system
```

This sets `PROMETHEUS_PORT` on the container, creates a headless
`goldmane-metrics` Service with `prometheus.io/scrape`
annotations, and opens the metrics port in the NetworkPolicy.

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

For the list of Goldmane-specific metrics and what they measure,
see [`goldmane/DESIGN.md`](./DESIGN.md#prometheus-metrics).

## Design and review criteria

Architecture and invariants live in
[`goldmane/DESIGN.md`](./DESIGN.md). Do not look here for gRPC
service shapes, BucketRing semantics, Prometheus metric meanings,
or env var contracts — look there.
