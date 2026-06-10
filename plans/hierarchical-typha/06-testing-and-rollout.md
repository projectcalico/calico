# WS-F: Testing, observability, docs & rollout

Cross-cutting workstream; tracks shared infrastructure the other workstreams
consume, plus the gates between milestones. Per repo rules, each functional PR
already carries its own tests — this plan covers the *shared* harness work,
the scale/soak campaign, and rollout sequencing.

## Shared test infrastructure

### 1. Chainable in-process harness (consumed by WS-A onward)

Extend `typha/fv-tests/server_harness_test.go`:

- Factor `ServerHarness` so its input can be either the test decoupler
  (today's behaviour) or a typha-client pipeline pointed at another harness's
  server port. Provide `ChainHarness(upstream *ServerHarness) *ServerHarness`.
- Parity assertion helper: walk two snapcaches' latest breadcrumbs and diff
  (keys, values, revisions, sync status) — used by WS-A/C/D/E tests; also a
  client-vs-cache variant using the existing recording `ClientState`.
- Fault hooks: kill/restart a harness's listener (reconnect tests); corrupt a
  cache entry via test-only hook (WS-D detection tests).
- Fake elector / fake slot-acquirer implementing the WS-B/WS-E interfaces so
  role transitions are scriptable in-process.

### 2. Felix FV multi-typha topology (consumed by WS-C, WS-E)

`felix/fv/infrastructure/typha.go` currently runs a single typha
(`RunTypha`). Add:

- `TopologyOptions.NumTyphas int` + `TyphaHierarchyEnabled bool`
  (+ `TyphaTier1Count` for WS-E); start N typha containers against the
  existing k8s-datastore infra (`K8sDatastoreInfra`) with leases RBAC.
- Helpers: `KillTyphaLeader()`, `CurrentTyphaLeader()` (read the Lease),
  await-felix-resync assertion.
- Keep the single-typha default untouched for the existing suite.

### 3. Scale / soak (pre-GA gate, not per-PR)

- Reuse/extend whatever drove the snapshot-sharing numbers (the Google doc's
  500-client × 500k-KV scenario): `typha/fv-tests` already has many-client
  tests; build a benchmark scenario: 1 leader + tier-1 + tier-2 in-process or
  containerised, 500k KVs, churn at ~1k updates/s, measure: end-to-end
  propagation latency (leader write → tier-2 client receipt), promotion
  failover time, CPU per tier, checksum overhead (on vs off).
- Soak: 24h churn + scripted leader kills every 10 min + random typha kills;
  zero checksum mismatches is the pass bar (this is the WS-D payoff: the soak
  *proves* reconciliation).
- Where: nightly Semaphore job (`.semaphore/semaphore.yml.d/` template +
  `make gen-semaphore-yaml`) or a manually-run make target first; decide with
  Shaun before automating.

## Observability (rolled into the WS PRs; inventoried here)

| Metric | WS |
|---|---|
| `typha_leader` / `typha_role` gauge, transitions counter | B/C/E |
| `typha_upstream_connected{syncer_type}`, reconnects counter | A |
| resync duration histogram (OnTyphaConnectionRestarted → InSync), per pipeline | A/C |
| `typha_checksum_mismatches_total`, last-compare gauge, checksum compute cost | D |
| per-tier connection counts; lease API call rate | E |

Log conventions: every role transition and source swap at INFO with a single
grep-able prefix (e.g. `Hierarchy:`), upstream identity in fields. Update the
Typha Prometheus docs page (tigera/docs repo — file a docs PR; label
`docs-pr-required` on the code PRs that add metrics).

## Documentation & design

- `typha/DESIGN.md`: created in WS-A; each WS appends its section (this is a
  repo rule, restated in every sub-plan).
- Operator support is its own workstream: `07-operator-integration.md`
  (tigera/operator repo; RBAC, env, services, client cert, Installation API,
  autoscaler). WS-C and WS-E calico-repo PRs get the `needs-operator-pr`
  label and reference the matching operator PR.

## Upgrade / version skew

- Protocol changes (WS-D checksum) are hello-negotiated; verified by
  back-compat fv-tests (old-client simulation, existing pattern).
- Rolling upgrade of a hierarchy-enabled deployment: leader release-on-cancel
  (WS-B) + PDB + maxSurge config in the chart keep a leader available;
  fv-test the full-deployment rolling restart (WS-C matrix).
- Enabling the feature on an existing cluster: flip chart value → typhas
  restart → first election. Disabling: reverse. Both directions FV-tested
  (WS-C).
- Mixed-version typhas (upgrade window): old typhas ignore leases and connect
  to the datastore directly — they just don't participate; data remains
  correct (they serve from their own watch). State this invariant in
  DESIGN.md and don't break it: hierarchy must degrade to "extra datastore
  watchers", never to wrong data.

## Rollout gates

| Gate | Criteria |
|---|---|
| M1 merge (WS-A) | chained fv-tests green incl. upstream-restart reconciliation; no-op when disabled |
| M2 merge (WS-C, after WS-B) | promotion/demotion UT+FV matrix green; felix FV leader-kill green |
| Checksums on by default (typha↔typha) | WS-D + zero mismatches across M2 suite + 24h soak |
| M3 merge (WS-E) | three-level FV green; lease QPS bounded; sizing math documented |
| GA / docs | scale campaign numbers published; docs PRs landed; operator story agreed |

## Release notes / PR hygiene (every WS PR)

- Use the PR template; real release note (feature is user-facing).
- Labels: `docs-pr-required` (or `docs-not-required` for pure-internal PRs),
  `release-note-required`.
- Generated files (`manifests/`, semaphore yml) committed with source.
