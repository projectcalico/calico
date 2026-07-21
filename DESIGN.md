# Calico — Architecture

This file is the repo-wide architecture index. Per-component
architecture, invariants, and review criteria live in each
component's `DESIGN.md` (linked below). Operational guidance —
build commands, test invocation, debugging, in-repo conventions
— lives in [`.claude/CLAUDE.md`](.claude/CLAUDE.md) at the root
and in each component's `CLAUDE.md` (or `AGENTS.md`).

If you're looking for *how* to do something in this repo, look in
`CLAUDE.md`. If you're looking for *what the code promises*, look
here or in the matching component's `DESIGN.md`.

## 1. Calico in one paragraph

Project Calico is a container networking and security platform
for Kubernetes. A typical deployment programs the per-node
dataplane (eBPF, iptables, nftables, or Windows) to enforce
network policy, route traffic, and report on flows; a small set
of cluster-wide controllers and a fan-out proxy coordinate the
nodes against the Kubernetes API or an etcd datastore. Optional
add-ons cover flow-log aggregation, UI, management-cluster
tunnelling, application-layer policy, and other Enterprise
features.

## 2. Components

### Core components (dependency order)

```
api/              - Calico API definitions (CRDs, protobuf), separate go.mod
libcalico-go/     - Core Go client library and data model
typha/            - Datastore fan-out proxy for scaling (reduces etcd load)
felix/            - Core per-host networking agent (eBPF/iptables/nftables dataplane)
node/             - Node initialization container (includes Felix, confd, BIRD, startup scripts)
calicoctl/        - CLI tool for Calico management
kube-controllers/ - Kubernetes-specific controllers (namespace, pod, node, serviceaccount)
cni-plugin/       - Kubernetes CNI integration
confd/            - Configuration management daemon
app-policy/       - Application layer policy (L7)
apiserver/        - Kubernetes API aggregation layer
```

### Additional components

```
goldmane/             - Log aggregation and flow log storage
guardian/             - Secure tunnel proxy for management cluster connections
pod2daemon/           - Flex volume driver for injecting credentials into pods
key-cert-provisioner/ - TLS certificate provisioner for Calico components
whisker/              - Flow log UI (TypeScript/React frontend)
whisker-backend/      - Backend for whisker flow log UI
e2e/                  - End-to-end test suites
release/              - Release tooling and automation
lib/std/              - Internal shared Go library (separate go.mod)
lib/httpmachinery/    - Internal HTTP utility library (separate go.mod)
```

### Per-component design

Components with their own design doc:

| Component | Design doc |
|---|---|
| Felix | [`felix/DESIGN.md`](felix/DESIGN.md) — index with topic sub-designs under [`felix/design/`](felix/design/) |
| Goldmane | [`goldmane/DESIGN.md`](goldmane/DESIGN.md) |
| Typha | [`typha/DESIGN.md`](typha/DESIGN.md) |
| Node container | [`node/DESIGN.md`](node/DESIGN.md) |

Components without a `DESIGN.md` inherit constraints from the
code and from this top-level overview. Adding a `DESIGN.md` when
a component's invariants warrant one is encouraged — see
[`felix/DESIGN.md`](felix/DESIGN.md) §5 for the shape to follow.

## 3. Cross-cutting patterns

### Combined `calico` binary

Most component daemons are registered as subcommands of a single
`calico` binary rather than shipping as independent binaries —
felix, confd, kube-controllers, goldmane, guardian,
whisker-backend, key-cert-provisioner, typha, dikastes, csi,
flexvol, and webhooks all dispatch through
`calico component <name>`. Inside the node container, runit
services exec the subcommand directly (see
`node/filesystem/etc/service/available/<name>/run`).

**Adding a new component:**

1. Expose a `NewCommand() *cobra.Command` from the component's
   package.
2. Register it in `cmd/calico/component.go` under
   `newComponentCommand`.
3. If the component runs in the node container, add a runit
   service at `node/filesystem/etc/service/available/<name>/run`
   whose body is `exec calico component <name>`.
4. The component's `Run` handler should call
   `logutils.ConfigureFormatter("<name>")` so log lines carry a
   consistent component prefix.

**Restart-on-config-change (exit 129):** A component can request
an in-place restart on a live config change by exiting with
`cmdwrapper.RestartReturnCode` (129) — currently felix and
kube-controllers do. The exit code only has an effect if *some*
outer supervisor re-launches the process on it, and the codebase
has three such supervisors depending on how the component is run:

- **runit**, in the node container, restarts a service when its
  `run` script's process exits. Felix runs this way:
  `node/filesystem/etc/service/available/felix/run` ends in
  `exec calico component felix`, and runit re-runs it on exit.
- **`felix/docker-image/calico-felix-wrapper`**, a bash loop that
  re-runs `calico component felix` whenever it exits 129. Used for
  the standalone felix image and FV, where runit isn't present.
- **`cmdwrapper.WrapSelf(innerEnvVar, fn)`** (`pkg/cmdwrapper`),
  an in-process self-re-exec for components that run with no
  external supervisor — currently only kube-controllers, whose
  container entrypoint is `calico component kube-controllers`
  directly. The outer invocation re-execs itself (setting
  `innerEnvVar=1`) on exit 129; the inner runs the daemon body.

When adding a component that wants exit-129 reload semantics, make
sure one of these supervisors covers it — a bare
`exec calico component <name>` with no supervising parent gives no
restart.

Notes specific to `cmdwrapper.WrapSelf` (the kube-controllers
path; see `kube-controllers/pkg/kubecontrollers/command.go`):

- Pick a unique `innerEnvVar` per component (e.g.
  `CALICO_KUBE_CONTROLLERS_INNER`). `WrapSelf` strips any
  pre-existing value before re-execing.
- The caller configures logrus before calling `WrapSelf`; `fn`
  is the inner daemon body.
- Don't change the log line format in `cmdwrapper` — integration
  tests grep stdout for `"Received exit status N, restarting"`.

### Health reporting

Components expose liveness/readiness through the shared
aggregator in `libcalico-go/lib/health`.

1. Construct once per component:
   `ha := health.NewHealthAggregator()`.
2. For each independent health source, register a named reporter
   declaring what it will report:
   `ha.RegisterReporter("Startup", &health.HealthReport{Live: true, Ready: true}, timeout)`.
   A non-zero timeout means reports must refresh before expiry
   or the aggregator treats that reporter as unhealthy — use
   this for long-running loops where silent stalls matter.
3. Call `ha.Report(name, &health.HealthReport{...})` at startup
   and as state changes inside running goroutines.
4. Serve the endpoints with `ha.ServeHTTP(enabled, host, port)`
   — this exposes `/readiness` and `/liveness` on the given
   port.

For Kubernetes probes, use the generic
`calico health --port=<port> --type=readiness|liveness` exec
command (`cmd/calico/health.go`) rather than adding a
per-component healthcheck binary or a bare `httpGet` probe. It
does the HTTP GET and exits 0 on 2xx/3xx — the standard for pods
running the combined image.

Examples worth copying from:
`kube-controllers/pkg/kubecontrollers/run.go` (Startup /
CalicoDatastore / KubeAPIServer reporters, no timeout) and
`felix/daemon/daemon.go` (lifecycle reporter plus per-subsystem
reporters with timeouts).

## 4. Go module structure

- Root `go.mod` (`github.com/projectcalico/calico`) is the
  primary module for most components.
- `api/go.mod` (`github.com/projectcalico/api`) is separate (API
  exported as an independent repo).
- `lib/std/go.mod` and `lib/httpmachinery/go.mod` are internal
  libraries with their own modules.
- When adding Go dependencies:
  `cd <component> && go mod tidy && cd .. && make check-go-mod`.

## 5. Entry points

| Path | Role |
|---|---|
| `cmd/calico/component.go` | Dispatcher for `calico component <name>` |
| `felix/daemon/daemon.go` | Felix main entry point |
| `felix/calc/` | Felix calculation graph (policy processing brain) |
| `felix/dataplane/` | Dataplane implementations (eBPF, iptables, nftables) |
| `node/pkg/lifecycle/startup/startup.go` | Node initialization |
| `calicoctl/calicoctl/calicoctl.go` | CLI entry point |
| `libcalico-go/lib/health/` | Shared health aggregator |
| `pkg/cmdwrapper/` | Exit-129 restart-on-config-change wrapper |

For deeper architecture (data flow, calculation-graph internals,
dataplane backends, BPF specifics), see the per-component design
docs above — Felix in particular has a fleshed-out family of
sub-designs under [`felix/design/`](felix/design/).
