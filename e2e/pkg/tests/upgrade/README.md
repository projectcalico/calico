# Upgrade scenarios

An upgrade scenario creates state on the old ("from") cluster, watches
connectivity while Calico rolls out, and checks the state afterwards. One Go
file and its YAML make a scenario. The `e2e-upgrade` ArgoCI cron runs them
weekly from n-1 and n-2 to master.

The feature developer adds or updates a scenario in the feature PR. Delivery
Engineering owns this framework and the cron.

## Adding a scenario

Create `scenarios/<name>.go` and put its YAML in `scenarios/testdata/<name>/`:

```go
//go:embed testdata/policy-survives
var policySurvivesFS embed.FS

var npGVR = schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"}

func init() {
	upgrade.Register(upgrade.Scenario{
		Name:     "policy-survives",
		Feature:  "NetworkPolicy",           // a key of describe's features map
		From:     []string{"v3.32", "v3.33"}, // RELEASE_STREAM values the cron runs
		Fixtures: upgrade.Sub(policySurvivesFS, "testdata/policy-survives"),
		Probes: []upgrade.Probe{
			{Name: "cli-80", Client: "cli", Target: "svc:srv:80", Protocol: "tcp", Expect: upgrade.AlwaysAllowed},
			{Name: "cli-8080", Client: "cli", Target: "svc:srv:8080", Protocol: "tcp", Expect: upgrade.AlwaysDenied},
		},
		Verify: func(ctx context.Context, e *upgrade.Env) error {
			return upgrade.ExpectField(ctx, e, npGVR, e.Namespace, "allow-80", "{.spec.ingress[0].destination.ports[0]}", 80)
		},
	})
}
```

`Register` panics at init on anything it can check statically, so
`go test ./pkg/tests/upgrade/...` catches most mistakes. The three scenarios
under `scenarios/` are worked examples: declarative only (`cnp-named-port`),
imperative seed against CRDs (`ipam-leak-and-live`), and objects created one
by one (`crd-invalid-stored`).

### Fixtures

- Raw YAML, server-side applied in lexical file order (field manager
  `e2e-upgrade`).
- Namespaced objects land in `e2e-upgrade-<name>`; naming another namespace is
  rejected.
- Cluster-scoped objects must be named `e2e-upgrade-<name>-*`.
- Cluster-scoped policy must be confined to the scenario namespace, because the
  normal suite runs between seed and verify. A GlobalNetworkPolicy's
  `namespaceSelector` must name it. A ClusterNetworkPolicy subject must pin
  `kubernetes.io/metadata.name` via `subject.namespaces.matchLabels` or
  `subject.pods.namespaceSelector.matchLabels`.
- Images must be ones `seed_images.sh` pre-loads; kubeadm cells can't pull from
  Docker Hub.

### Version skew

The e2e binary comes from the master hashrelease, so `Seed` is master code
running against a v3.32 or v3.33 cluster.

- Fixtures use only kinds and fields that exist in the oldest `From` stream,
  and `projectcalico.org/v3` for Calico resources.
- `Seed` must not use master's typed Calico clients. Use `Env.Dynamic`, or the
  `Resource`/`Create`/`Get` helpers.
- `Verify` runs on the upgraded cluster, so any client is fine.

### Probes

Each probe runs as a netshoot Deployment, `probe-<name>`, that copies the labels
and service account of the fixture Pod named in `Client`. Policy therefore
treats it as that client. Each attempt is a fresh connection
(`nc -z`/`curl -sf`) once a second, and is logged with a timestamp.

- Clients must be bare Pods, and no fixture Service may select them.
- `Target` is `svc:<name>:<port>` (in-namespace) or `ip:<addr>:<port>`.
- Verify slices the log against the upgrade window and checks each slice
  against `Expect{Before, During, After}`:

| Slice | Range |
|---|---|
| Before | warm-up → `start − 5s` |
| During | `start − 5s` → `end + Settle` (default 60s) |
| After | the next 2 minutes |

- `Allowed` passes with at most `MaxConsecutiveFails` (default 2) consecutive
  failed attempts. `Denied` fails on a single success. `Any` isn't checked.
- A `svc:` target that is expected `Denied` in a slice needs another probe
  expecting `Allowed` in the same slice. Without that positive control, a dead
  target would pass.
- The spec fails as **inconclusive**, not as a Calico failure, when a prober
  pod restarted or was rescheduled, a slice is empty, the log was rotated, or
  lines are more than 10s apart.

Probes only see pod-to-pod traffic. Check control-plane state such as BGP,
routes or IPAM in `Verify`, via `Get`, `ExpectField` or `ExecCalicoNode`.

### Lane selection and `Serial`

- Nothing calls `Skip()`. A scenario that some lanes can't run carries a label
  those lanes already exclude (e.g. `describe.RequiresCalicoIPAM()`,
  `RequiresBGP`, `Dataplane:BPF`).
- Set `Serial` when Seed patches cluster-wide config (Felix or
  KubeControllers configuration), or when a cluster-scoped fixture could change
  what other specs see. Restore patched values in a verify `DeferCleanup`.
  Pick values that are harmless to the specs that run in between.

### Retirement

`scenarios_test.go` fails if a scenario's `From` shares no stream with
`.argoci/cron/e2e-upgrade.yaml`. When the cron moves on, delete the scenario or
update `From`.

## How it runs

Each scenario becomes two specs under `[upgrade] <name>`:
- `seed`, labelled `Upgrade:Seed`;
- `verify`, labelled `Upgrade:Verify`.

Both also carry `UpgradeFrom:<stream>` for each entry in `From`.

`base.yaml` excludes both labels, so normal lanes never select them. Two env
vars, applied by `testconfig.ApplyUpgradePhase`, reopen them:

| `E2E_UPGRADE_PHASE` | Selection |
|---|---|
| unset | upgrade specs stay excluded |
| `seed` | **only** `Upgrade:Seed && UpgradeFrom:$E2E_UPGRADE_FROM`, keeping the lane's other excludes |
| `verify` | the lane's normal scope, **plus** `Upgrade:Verify && UpgradeFrom:$E2E_UPGRADE_FROM` |

In CI (`.argoci/scripts/body_standard.sh`) the order is:

provision → install → seed_images → configure → **pre_upgrade** → migrate → load_images → run_tests

| Phase | What happens |
|---|---|
| `pre_upgrade.sh` | Runs `run_tests.sh` with `E2E_UPGRADE_PHASE=seed`, writing `junit-upgrade-seed.xml`. A failure doesn't stop the job: the scenario's verify then fails with "no seed record". It is skipped when the hashrelease doesn't ship `e2e/config/upgrade/scenarios.yaml`, because older binaries ignore `E2E_UPGRADE_PHASE` and would run the whole lane. |
| `migrate.sh` | Writes ConfigMap `e2e-upgrade-system/upgrade-window` (`start`, `end`, `result`). `end` is recorded once calico-node, kube-controllers, typha and the TigeraStatuses have settled, not when `bz upgrade` returns. A failed upgrade or rollout stops the job. |
| `run_tests.sh` | The normal post-upgrade suite, plus the verify specs. |

### State between phases

- **Seed** recreates the namespace, applies fixtures, starts and warms up
  probers, runs `Seed`, and writes the seed record **last** (ConfigMap
  `seed-record` in the scenario namespace). A missing record means seeding
  didn't finish. `Seed` may store its own data in `Env.Record.Values`.
- **Verify** waits until the After slice has elapsed, judges probes, then runs
  `Verify`. On pass it deletes the namespace and the scenario's cluster-scoped
  objects. On failure they stay for diags.

### Running locally

Point the e2e binary at a cluster running the from-stream:
1. run with `E2E_UPGRADE_PHASE=seed E2E_UPGRADE_FROM=v3.33`;
2. upgrade, writing the `upgrade-window` ConfigMap as `migrate.sh` does;
3. run with `E2E_UPGRADE_PHASE=verify`.

Re-running seed resets the scenario namespace.
