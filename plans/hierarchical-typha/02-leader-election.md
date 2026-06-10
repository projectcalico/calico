# WS-B: Kubernetes Lease-based leader election in Typha

## Goal

Give Typha a leader-election subsystem using upstream Kubernetes best practice:
`k8s.io/client-go/tools/leaderelection` with a `resourcelock.LeaseLock`
(coordination.k8s.io/v1 Leases). Kubernetes-datastore mode only — no etcd
support, no abstraction layer (per project decision).

This workstream lands the election machinery, identity plumbing, RBAC, and
chart changes, but keeps it **inert**: the election result is exposed via a
channel/callback, logged, and surfaced in metrics/health, and is consumed by
WS-C. This keeps the PR reviewable and independently mergeable.

Calico has **no existing leader-election usage anywhere in the monorepo**
(verified), so this also sets the repo-wide pattern — keep the package clean
and component-agnostic where cheap (suggested location:
`typha/pkg/leaderelection`, promotable later if other components want it).

## Required reading

- `plans/hierarchical-typha/00-overview.md`
- client-go `tools/leaderelection` package docs (in module cache,
  `k8s.io/client-go@v0.36.1/tools/leaderelection/leaderelection.go` — read the
  package comment carefully: it is *not* a strict guarantee of single leader
  ("best-effort"; relies on bounded clock skew), and the standard mitigations
  (renewDeadline ≪ leaseDuration, observe `ReleaseOnCancel` semantics).
- `typha/pkg/k8s/lookup.go:39` — `RealK8sAPI` clientset construction
  (`winutils.BuildConfigFromFlags` → `kubernetes.NewForConfig`); reuse this
  clientset.
- `typha/pkg/daemon/daemon.go` — `Start()` for where subsystems launch;
  health aggregator wiring (~392-398).
- `charts/calico/templates/calico-typha.yaml` (Deployment env, ~lines 89-149)
  and `charts/calico/templates/calico-node-rbac.yaml` (Typha runs as the
  `calico-node` ServiceAccount).
- `typha/pkg/config/config_params.go` — config tag pattern.

## Design

### Election wrapper

`typha/pkg/leaderelection`:

```go
type Config struct {
    Enabled         bool
    LeaseName       string        // default "calico-typha-leader"
    LeaseNamespace  string        // default: own pod namespace
    Identity        string        // default: POD_NAME (fallback hostname+UUID suffix)
    LeaseDuration   time.Duration // default 15s  \
    RenewDeadline   time.Duration // default 10s   } client-go recommended ratios
    RetryPeriod     time.Duration // default 2s   /
}

type Elector struct { ... }

// Roles delivered on a channel; consumers (WS-C) treat each transition as
// edge-triggered. Elector keeps running forever, re-entering the election on
// leadership loss.
type Role int // Follower, Leader
func New(cs kubernetes.Interface, cfg Config) *Elector
func (e *Elector) Run(ctx context.Context)
func (e *Elector) Roles() <-chan Role
func (e *Elector) CurrentHolder() (string, bool)  // last observed holder identity, for discovery in WS-C
```

Implementation notes:

- Use `leaderelection.RunOrDie`-style loop but **not** `RunOrDie` itself —
  on `OnStoppedLeading` we must demote, not exit. Loop:
  `le.Run(ctx)` returns when leadership is lost → emit `Follower` → re-run.
- `OnNewLeader` callback feeds `CurrentHolder()` (WS-C uses this to find the
  leader's address; record holder identity == pod name).
- `ReleaseOnCancel: true` so a gracefully-stopping leader releases the lease
  immediately (fast failover during rolling upgrade; pairs with Typha's
  graceful shutdown — hook lease release into `ShutDownGracefully()` ordering
  in WS-C).
- Identity string: `POD_NAME` (downward API). Append nothing — pod names are
  unique, and the identity must be resolvable back to a pod for discovery.
- Clock-skew caveat: with `LeaseDuration` 15s there is a small window where
  two Typhas both believe they lead. WS-C must tolerate this (two Typhas
  running real syncers briefly is safe — both serve correct data; the extra
  datastore load is transient). Document in DESIGN.md; never build anything
  that corrupts state under dual-leadership.

### Pod identity plumbing

Typha pods currently get **no** downward-API env. Add to
`charts/calico/templates/calico-typha.yaml` (and `make gen-manifests`):

```yaml
- name: TYPHA_PODNAME
  valueFrom: { fieldRef: { fieldPath: metadata.name } }
- name: TYPHA_PODNAMESPACE
  valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
- name: TYPHA_NODENAME            # needed by WS-C/E for same-node preference
  valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
```

Config params: `PodName`, `PodNamespace`, `NodeName` (+ the election params
`LeaderElectionEnabled`, `LeaseName`, `LeaseNamespace`, durations). Note the
discovery code and operator deployments may use different env conventions —
grep for prior art (`K8sNamespace` default is `kube-system` in typha config)
and stay consistent.

### RBAC

`charts/calico/templates/calico-node-rbac.yaml` (the ClusterRole used by
Typha's SA): add

```yaml
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "create", "update"]
```

Consider a namespaced Role instead (leases live in one namespace) — but the
existing file is a ClusterRole shared with calico-node; follow whichever shape
the chart maintainers use for similar narrow grants. If `resourceNames`
restriction is feasible for `get`/`update` (it is; not for `create`), use it.
Regenerate `manifests/`.

### Health & metrics

- Register a health reporter ("LeaderElection") on the existing
  `health.HealthAggregator`: live as long as the elector loop is running.
  Don't gate readiness on being leader.
- Prometheus: `typha_leader` gauge (1/0), `typha_leader_transitions_total`
  counter, holder identity as a label on an info-style gauge.

## Tasks

1. Read required reading; confirm client-go version & leaderelection API
   surface in the module cache.
2. Implement `typha/pkg/leaderelection` with fake-clientset UTs (client-go's
   `k8s.io/client-go/kubernetes/fake` supports leases): acquire, lose (delete/
   steal lease), re-acquire; `Roles()` edge sequence; `CurrentHolder()`.
3. Config params + UT.
4. Daemon wiring (`daemon.go Start()`): construct elector when enabled, reuse
   the `RealK8sAPI` clientset (may need a small accessor — clientset is
   currently private to `typha/pkg/k8s`); log + metrics on transitions.
5. Chart + RBAC + `make gen-manifests`; commit generated files.
6. DESIGN.md: add "Leader election" section (guarantees, dual-leader window,
   parameter ratios).

## Test matrix (same PR)

- UT as above (fake clientset; simulated lease steal → Follower emitted; lease
  free → Leader re-emitted).
- UT: graceful-cancel releases lease (`ReleaseOnCancel`).
- Integration smoke (typha fv-tests or a `k8s`-tagged UT against envtest if
  available — check whether the repo has envtest infra; if not, fake-clientset
  UT suffices for this PR, with real-cluster coverage arriving via WS-C's FV).
- `make -C typha ut` green; `make gen-manifests` produces no dirty diff after
  commit.

## Acceptance criteria

- With election enabled on an N-replica Typha deployment, exactly one logs/
  reports leadership (steady state); kill it → another acquires within
  ~LeaseDuration; metrics reflect transitions.
- Election disabled (default) → zero behaviour change.

## Out of scope

Acting on the role (WS-C). Multi-slot/tier-1 election (WS-E — but keep the
wrapper generic: lease name is a parameter, and the Role enum should not
hard-code "the" leader concept in a way that blocks N parallel electors).
