# Whisker Development Guide

Whisker is the flow log visualization UI for Calico. It consists of two components deployed in a single pod: the **React frontend** (nginx, port 8081) and the **Go backend** (port 3002). The backend proxies HTTP requests to Goldmane's gRPC API.

## Architecture

```
Browser → nginx (:8081) → React SPA
                        → /whisker-backend/* → whisker-backend (:3002) → Goldmane (:7443 gRPC)
```

- **whisker/** — React/TypeScript SPA (this directory)
- **whisker-backend/** — Go HTTP-to-gRPC bridge
- **goldmane/** — Flow aggregation service (see `goldmane/CLAUDE.md`)

### Tech Stack

| Layer     | Tech                                                             |
| --------- | ---------------------------------------------------------------- |
| Frontend  | React, TypeScript, TailwindCSS, Chakra UI, Radix UI              |
| Build     | Rsbuild (Rspack-based)                                           |
| State     | Zustand, TanStack React Query                                    |
| Testing   | Jest, React Testing Library                                      |
| Backend   | Go, net/http, lib/httpmachinery                                  |
| Protocol  | HTTP/JSON ↔ gRPC/protobuf (via whisker-backend)                 |
| Streaming | EventSource (SSE) in browser → HTTP chunked → gRPC server stream |

## Frontend Structure (`whisker/`)

```
src/
├── main.tsx                     # Entry point
├── App.tsx                      # Root component, router
├── api/                         # API client (fetch + EventSource streaming)
├── features/
│   ├── flowLogs/                # Main feature: flow log table, filters, details
│   │   ├── components/
│   │   │   ├── OmniFilters/     # Filter dropdowns (policy, namespace, action, etc.)
│   │   │   ├── FlowLogsList/    # Flow table with sorting/pagination
│   │   │   └── FlowDetailsPanel # Expanded flow: policy trace, labels
│   │   └── hooks/               # Data fetching hooks
│   └── promotions/              # Banner content
├── components/                  # Shared UI components
├── hooks/                       # Custom React hooks
├── types/                       # TypeScript type definitions
├── utils/                       # Utility functions
└── theme/                       # Theme configuration
```

### Key Frontend Concepts

**Streaming**: `src/api/index.ts` implements `useStream()` using EventSource (SSE). Flows are buffered (20k limit) and throttled (1s) before updating the UI.

**OmniFilters**: The filter bar uses `/flows-filter-hints` for autocomplete. Filters cascade — selecting a policy kind narrows the available namespace/name hints.

**Environment**: `APP_API_URL` (default `/whisker-backend/`) controls the backend URL. Set via nginx config injection at runtime.

## Backend Structure (`whisker-backend/`)

```
cmd/
├── main.go                      # Entry point
└── app/app.go                   # Application setup (gRPC client, HTTP server)
pkg/
├── config/api.go                # Config from env vars
├── handlers/v1/
│   ├── flows.go                 # HTTP handlers for /flows and /flows-filter-hints
│   └── protoconvert.go          # HTTP JSON ↔ protobuf conversion
└── apis/v1/
    └── flows.go                 # Request/response Go types (Filters, FlowResponse, etc.)
```

### Configuration

| Env Var         | Default                           | Description                                               |
| --------------- | --------------------------------- | --------------------------------------------------------- |
| `GOLDMANE_HOST` | `goldmane.calico-system.svc:7443` | Goldmane gRPC address                                     |
| `HOST`          | `0.0.0.0`                         | HTTP listen address                                       |
| `PORT`          | `8080`                            | HTTP listen port (in-cluster deployment sets `PORT=3002`) |
| `LOG_LEVEL`     | `info`                            | Log level                                                 |
| `CA_CERT_PATH`  | `/etc/pki/tls/certs/ca.crt`       | CA cert for Goldmane mTLS                                 |
| `TLS_CERT_PATH` | —                                 | Client cert for Goldmane mTLS                             |
| `TLS_KEY_PATH`  | —                                 | Client key for Goldmane mTLS                              |

## HTTP API

### GET /flows

Query or stream flow logs.

**Parameters:**
| Param | Type | Description |
|---|---|---|
| `watch` | bool | `true` = SSE stream, `false` = list response (no server-side pagination) |
| `startTimeGte` | int64 | Relative seconds (e.g., `-60` = last minute) |
| `startTimeLt` | int64 | Upper bound (relative seconds) |
| `sortBy` | string | Sort fields; repeatable (e.g., `?sortBy=startTime&sortBy=sourceName`) |
| `filters` | JSON | URL-encoded filter object (see below) |

### GET /flows-filter-hints

Returns available values for a filter field (autocomplete).

**Parameters:**
| Param | Type | Description |
|---|---|---|
| `type` | enum | Required. One of: `DestName`, `SourceName`, `DestNamespace`, `SourceNamespace`, `PolicyTier`, `PolicyName`, `PolicyKind`, `PolicyNamespace` |
| `page`, `pageSize` | int | Pagination |
| `filters` | JSON | Restrict hints to flows matching these filters |

### Filter JSON Structure

```json
{
    "source_names": [{ "type": "Exact", "value": "pod-*" }],
    "source_namespaces": [{ "type": "Exact", "value": "frontend" }],
    "dest_names": [{ "type": "Exact", "value": "api-*" }],
    "dest_namespaces": [{ "type": "Exact", "value": "backend" }],
    "protocols": [{ "type": "Exact", "value": "tcp" }],
    "dest_ports": [{ "type": "Exact", "value": 53 }],
    "actions": ["Allow", "Deny", "Pass"],
    "pending_actions": ["Allow", "Deny"],
    "reporter": "Src",
    "policies": [
        {
            "kind": "CalicoNetworkPolicy",
            "tier": { "type": "Exact", "value": "security" },
            "name": { "type": "Exact", "value": "my-policy" },
            "namespace": { "type": "Exact", "value": "default" }
        }
    ]
}
```

**Key rules:**

- `reporter` is a single string (`"Src"` or `"Dst"`), NOT an array
- `kind` in policy filters is a bare string, NOT a FilterMatch
- All other fields use FilterMatch: `{"type": "Exact"|"Fuzzy", "value": ...}`
- Multiple policy objects = OR; fields within one object = AND
- `dest_ports` value is an integer, not string: `{"type": "Exact", "value": 53}`

### FlowResponse Structure

```json
{
    "start_time": "2026-03-19T14:30:00Z",
    "end_time": "2026-03-19T14:31:00Z",
    "action": "Allow",
    "source_name": "traffic-gen-*",
    "source_namespace": "frontend",
    "source_labels": "app=traffic-gen | role=client",
    "dest_name": "api-*",
    "dest_namespace": "backend",
    "dest_labels": "app=api | role=backend",
    "protocol": "tcp",
    "dest_port": 8080,
    "reporter": "Src",
    "policies": {
        "enforced": [
            {
                "kind": "...",
                "name": "...",
                "namespace": "...",
                "tier": "...",
                "action": "...",
                "policy_index": 0,
                "rule_index": 0,
                "trigger": null
            }
        ],
        "pending": [
            {
                "kind": "...",
                "name": "...",
                "namespace": "...",
                "tier": "...",
                "action": "...",
                "policy_index": 0,
                "rule_index": 0,
                "trigger": null
            }
        ]
    },
    "packets_in": 100,
    "packets_out": 50,
    "bytes_in": 5000,
    "bytes_out": 2500
}
```

### Valid Enum Values

| Field            | Values                                                                                                                                                                                             |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Action           | `Allow`, `Deny`, `Pass`                                                                                                                                                                            |
| Reporter         | `Src`, `Dst`                                                                                                                                                                                       |
| PolicyKind       | `CalicoNetworkPolicy`, `GlobalNetworkPolicy`, `NetworkPolicy`, `StagedNetworkPolicy`, `StagedGlobalNetworkPolicy`, `StagedKubernetesNetworkPolicy`, `Profile`, `EndOfTier`, `ClusterNetworkPolicy` |
| FilterMatch type | `Exact`, `Fuzzy`                                                                                                                                                                                   |

### Special Display Transformations

- Namespace `"-"` or `""` → displayed as `"Global"` in hints
- Name `"pub"` → `"PUBLIC NETWORK"`, `"pvt"` → `"PRIVATE NETWORK"`

## Build & Test

### Frontend (whisker/)

```bash
make build              # yarn build → dist/
make install            # yarn install
make yarn-test          # Jest with coverage (~230 test files)
make format             # Prettier check
make lint               # ESLint check
make ci                 # All checks (lint + format + tests)
make image              # Build Docker image (nginx + dist/)
```

For development: `yarn start` runs Rsbuild dev server with hot reload.

### Backend (whisker-backend/)

```bash
make -C whisker-backend build    # Compile binary
make -C whisker-backend ut       # Unit tests (6 test files)
make -C whisker-backend image    # Build Docker image
```

Direct: `cd whisker-backend && go test ./...`

## Deployment

Both components run in a single Kubernetes pod:

| Container       | Port | Serves                                                         |
| --------------- | ---- | -------------------------------------------------------------- |
| whisker (nginx) | 8081 | React SPA + reverse proxy `/whisker-backend/` → localhost:3002 |
| whisker-backend | 3002 | HTTP API, connects to goldmane:7443 via mTLS                   |

Nginx config: `whisker/docker-image/default.conf`

## Debugging on a Running Cluster

```bash
# Port-forward to whisker UI
kubectl port-forward -n calico-system svc/whisker 8081:80

# Check whisker pod logs (both containers)
kubectl logs -n calico-system -l k8s-app=whisker -c whisker-backend
kubectl logs -n calico-system -l k8s-app=whisker -c whisker

# Quick flow check via API
curl -s "http://localhost:8081/whisker-backend/flows?watch=true&startTimeGte=-60" --max-time 5

# Check available filter hints
curl -s "http://localhost:8081/whisker-backend/flows-filter-hints?type=PolicyKind&pageSize=20"
curl -s "http://localhost:8081/whisker-backend/flows-filter-hints?type=PolicyTier&pageSize=20"
curl -s "http://localhost:8081/whisker-backend/flows-filter-hints?type=SourceNamespace&pageSize=20"
```

## Key Source Files

| File                                              | Purpose                            |
| ------------------------------------------------- | ---------------------------------- |
| `whisker/src/api/index.ts`                        | API client + SSE streaming         |
| `whisker/src/features/flowLogs/`                  | Main flow log feature              |
| `whisker/docker-image/default.conf`               | Nginx reverse proxy config         |
| `whisker-backend/pkg/handlers/v1/flows.go`        | HTTP handlers                      |
| `whisker-backend/pkg/handlers/v1/protoconvert.go` | JSON ↔ protobuf conversion        |
| `whisker-backend/pkg/apis/v1/flows.go`            | Go types (Filters, FlowResponse)   |
| `goldmane/proto/api.proto`                        | Source of truth for all data types |
