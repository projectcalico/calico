# whisker-backend glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `whisker-backend/`. The Whisker UI in `whisker/` is served by nginx, which proxies data requests to whisker-backend.

## Building blocks

The top layer of the whisker-backend process.

| Building block | Code | Responsible for |
|---|---|---|
| App | `whisker-backend/cmd/whiskerbackend/app.go` (`Run`) | Builds the HTTPS server that exposes `/flows` and `/flows-filter-hints`. |
| Flows handler | `whisker-backend/pkg/handlers/v1/flows.go` (`NewFlows`) | Serves a list or an event stream of flows and filter hints, applying the visibility filter. |
| Flows backend | `whisker-backend/pkg/apis/v1/backend.go` (`FlowsBackend`) | The interface the handler reads flows from, so it does not depend on one upstream. |
| Goldmane upstream | `whisker-backend/pkg/upstream/goldmane/backend.go` (`Backend`) | Implements the flows backend by calling Goldmane's `Flows` gRPC service. |
| Visibility filter | `whisker-backend/pkg/auth/filter.go` (`FlowFilter`) | Per-request check that admits a flow and redacts policy hits the user may not view. |
| Whisker nginx proxy | `whisker/docker-image/default.conf` | Serves the UI and strips the `/whisker-backend/` prefix before proxying to whisker-backend. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Filter hints](../GLOSSARY.md#filter-hints)
- [Query filter](../GLOSSARY.md#query-filter)

**Flows backend**:
The interface whisker-backend reads flows from. An upstream that can also stream implements the streaming variant, and watch requests are rejected for one that does not.
Code: `whisker-backend/pkg/apis/v1/backend.go` (`FlowsBackend`).
_Avoid_: backend, unqualified; upstream (that is the package name)

**Streaming flows backend**:
A flows backend that can also return a stream of flows. The Goldmane upstream implements it.
Code: `whisker-backend/pkg/apis/v1/backend.go` (`StreamingFlowsBackend`).
_Avoid_: backend on its own (it means several things)

**FlowResponse**:
The JSON form of one Goldmane Flow that whisker-backend returns. Whisker's UI types call the same record a flow log, which is not Felix's flow log.
Code: `whisker-backend/pkg/apis/v1/flows.go` (`FlowResponse`).
_Avoid_: flow log

**List-or-stream**:
One endpoint that returns a JSON list, or a server-sent event stream when the `watch` query parameter is set.
Code: `lib/httpmachinery/pkg/apiutil/handler.go` (`NewJSONListOrEventStreamHandler`).
_Avoid_: watch

**Visibility filter**:
The per-request `FlowFilter` that decides whether the current user may see a flow and redacts the policy hits on an admitted flow that the user may not view. No filter is installed unless the process is given a `FlowFilterFactory`.
Code: `whisker-backend/pkg/auth/filter.go` (`FlowFilter`).
_Avoid_: RBAC filter, filter (a query filter is a different thing)

**Pending actions**:
The actions that staged policies would have taken on a flow, from Goldmane's pending policy trace.
Code: `whisker-backend/pkg/apis/v1/flows.go` (`PendingActions`).
_Avoid_: staged actions

**Proxy prefix**:
The `/whisker-backend/` path prefix that the Whisker nginx container strips before proxying a request to whisker-backend.
Code: `whisker/docker-image/default.conf`.
_Avoid_: nothing known
