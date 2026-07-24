# Cross-monorepo performance-result publishing

This directory is the canonical home for plumbing that gets perf-test
measurements into the Lens Elasticsearch cluster, where they can be tracked
over time.

## Why this exists

The monorepo has a growing collection of perf tests -- tiger-bench,
`felix/k8sfv`, OpenStack Neutron→etcd resync timings, and others -- but
historically their results have been ephemeral: printed to a CI log, then lost
when the log rotates.  That makes it impossible to answer questions like "did
this PR slow down endpoint programming?" or "has Felix memory occupancy been
creeping up over the last quarter?"

The Lens ES/Kibana stack at `banzai-lens.dev-tools.tigera.net` gives us a
place to land structured perf data and visualise it over time.  This README
covers how to wire a new test into it.  Tiger-bench's
`pkg/elasticsearch/elasticsearch.go` is prior art and worth reading if you're
curious about the lower-level ES client side; this directory abstracts that
away behind a producer-side "write JSON files" contract.

This is **not** about per-PR perf gating (synchronous, blocks merges).  It's
about long-term trend visibility: spotting gradual regressions, validating
performance work, and comparing dataplanes/branches over time.

## The Lens store

- **ES + Kibana**: <https://banzai-lens.dev-tools.tigera.net>
- **Existing dashboards**: tiger-bench results live at
  `/app/dashboards#/view/856d49ee-c097-4c58-a6e7-1433475698fc`.
- **Credentials and endpoint**: ask in `#banzai` (or whoever owns the Lens
  cluster) for the ES endpoint URL (set as `ELASTICSEARCH_URL` -- typically
  on port 9200, distinct from the Kibana URL above) plus *one* of:
  - `ELASTICSEARCH_USER` + `ELASTICSEARCH_TOKEN` (basic auth), or
  - `ELASTICSEARCH_KEY` (API key -- preferred).
- **In CI**: wire these as Semaphore secrets attached to the pipeline that
  runs your test.
- **Locally**: same env vars work, but see [Operational hygiene](#operational-hygiene)
  -- don't pollute trend data with dev runs.

## What lives here

```
hack/perf/
├── cmd/send-perf-results/main.go     The tool that pushes JSON docs to ES.
├── index-templates/<family>.json     One ES index template per family.
└── README.md                         (this file)
```

## How a test publishes a measurement

A test producing perf data does **two** things:

1. Write one JSON file per measurement to
   `artifacts/perf/<index_family>/<descriptive_name>.json`.  Each file is a
   single ES document containing **only the scenario-specific scalars** --
   scale dimensions, metrics, test_name, and so on.  CI metadata
   (`git_commit`, `ci_run_id`, etc.) is NOT the producer's job.  See
   [Schema](#schema-what-makes-a-good-datapoint) below for what counts as
   scenario-specific.

2. Arrange for `send-perf-results` to run once at the end of the producing
   Semaphore job.  The simplest pattern is to add a line near the end of the
   job's commands:

   ```sh
   go run ./hack/perf/cmd/send-perf-results --dir artifacts/perf
   ```

   (or invoke a pre-built binary).  Calling it exactly once per job is the
   only operational discipline required -- see [Idempotency](#idempotency).

`artifacts/perf/` lives under the existing `artifacts/` upload, so the
per-measurement JSON files are also automatically captured as Semaphore
artifacts -- useful for post-mortem when a number looks off.

## What `send-perf-results` does

On each invocation, in order:

1. **Apply index templates.**  For every `hack/perf/index-templates/<family>.json`,
   PUT it to `/_index_template/<family>` in ES.  Idempotent upsert -- see
   [When does the PUT have effect?](#when-does-the-put-have-effect) for what
   this is and isn't buying.
2. **Walk `artifacts/perf/<family>/*.json`** for every `<family>` subdirectory.
3. **Augment each doc** with CI metadata (`@timestamp`, `git_commit`,
   `git_branch`, `code_version`, `ci_run_id`, `pr_number`, `env`) unless the
   producer already supplied that field -- producer values win.  Picked up
   from `SEMAPHORE_GIT_SHA`, `SEMAPHORE_GIT_BRANCH`, `SEMAPHORE_JOB_ID`,
   `SEMAPHORE_GIT_PR_NUMBER`.
4. **POST to `<family>_<UTC year>/_doc`.**  The year suffix is computed at
   send time; producer side stays date-free.  ES auto-creates the dated
   index on first write using the template applied in step 1.
5. Exit 0.

"Lens is observability, not a critical path": the tool only returns non-zero
in genuinely unrecoverable cases.  Missing credentials, unreachable ES,
malformed JSON, mapping conflicts -- all log a warning and continue.  A
`--require-creds` flag flips the missing-creds case to a hard failure, for
places that want a strict gate on the publish step.

### When does the PUT have effect?

Index templates in Elasticsearch apply at *index-creation* time, not to live
indices.  Once `benchmark_data_<family>_2026` exists, its mapping is fixed;
PUTing the template again does not modify that index.  So the PUT-every-time
behaviour is meaningful in four narrow cases:

1. **First-ever run for a family** -- creates the template before the first
   doc lands, so the first auto-created index gets pinned types instead of
   ES's dynamic inference.
2. **Year rollover** -- the next `benchmark_data_<family>_<YYYY>` is
   auto-created on the first write of the new year, using whatever template
   is in cluster state at that moment.
3. **Cluster rebuild or migration** -- equivalent to case (1).
4. **Defensive replay** -- if anything ever deletes the template (master
   failover edge cases have been known to lose entries), the next run puts
   it back.

In normal steady-state operation -- template already in place, mid-year --
the PUT is a no-op.  We do it on every run anyway because (a) it's a single
HTTP per family per CI job, effectively free, and (b) the self-heal property
in case (4) is worth more than the cost.

Mid-year template *edits* (adding/removing/renaming a field, changing a type)
do not affect the live index.  An added field gets dynamic-mapping inference
on first sight; a removed field still appears in old docs' `_source` and the
live index's mapping; a type change risks a write rejection (mapping
conflict) until the next year's index rolls over with the new template.  For
type changes that need to take effect mid-year, reindex into a renamed index
(`_2026_v2`) rather than fighting the existing mapping.

## Schema: what makes a good datapoint

**One measurement = one document.**  Don't push your test's whole raw output
as a single deeply-nested doc; decompose it into individual scalar
measurements first.

**Flat scalars only.**  Every field should be a scalar (string, number,
boolean) or a flat array of scalars.  Avoid:

- **Nested objects** (e.g. `cold.phases.endpoints.compare_ms`).  They
  technically work, but they're harder to discover in Kibana and they make
  visualisations clunkier than they need to be.
- **Arrays of objects** (e.g. `steady: [{phases: ...}, {phases: ...}]`).
  ES's default mapping flattens these into parallel arrays-of-scalars,
  losing per-element correlation.  Lens can't chart them; the proper fix
  (mapping the field as `nested` type) makes them queryable but Lens *still*
  won't chart them -- you'd have to drop down to TSVB or Vega.

If your test produces multiple sub-measurements (e.g. a "cold" run plus
three "steady" iterations), explode them into separate documents
distinguished by `phase` / `iter` / `test_step` fields.  See
[Patterns for tricky cases](#patterns-for-tricky-cases).

### Producer-supplied fields

Scenario-specific scalars are the producer's responsibility:

- **`test_name`** -- a stable string identifying the scenario family,
  distinct from the index name (e.g. `neutron_resync`).
- **Scale parameters** -- e.g. `scale_endpoints: 10000`, `scale_policies:
  100`, `scale_hosts: 10`.  Field names should be specific to your scenario,
  but consistent within a test.
- **The measured metrics**, flattened (e.g. `endpoints_total_ms`, not
  `endpoints.total_ms`).
- **`phase` / `iter` / `test_step` keywords** if the doc is one of several
  related sub-measurements.
- **`ok: bool`** and optional **`error: string`** if the test can partially
  succeed.
- **Scenario context** when applicable: `dataplane` (`iptables`,
  `nftables`, `ebpf`), `encap` (`vxlan`, `ipip`, `none`), `k8s_version`,
  `cloud` (`gcp`, `aws`, `azure`, `kind`), `node_type`, `node_count`.

### Tool-injected fields (don't set these)

`send-perf-results` adds these from the CI environment unless the producer
already supplied a value (producer wins):

- **`@timestamp`** -- ISO-8601 UTC; Kibana's time field.
- **`git_commit`** -- from `SEMAPHORE_GIT_SHA`.
- **`git_branch`** -- from `SEMAPHORE_GIT_BRANCH`.
- **`code_version`** -- short SHA derived from `git_commit`.
- **`ci_run_id`** -- from `SEMAPHORE_JOB_ID`.
- **`pr_number`** -- from `SEMAPHORE_GIT_PR_NUMBER`, if set.
- **`env`** -- `ci` if `SEMAPHORE_JOB_ID` is set, else `dev`.  Filter
  dashboards to `env: ci` to keep dev runs out of trend data.

### `phase` vs `iter` vs `test_step`

- **`iter`** *(integer)*: index of a repeated whole-test iteration
  (e.g. `0` for cold, `1..N` for steady runs).
- **`phase`** *(keyword)*: tag for distinct phases of a test (`cold`,
  `steady`, `setup`, `teardown`).  Use alongside `iter` when each phase is
  run multiple times.
- **`test_step`** *(keyword)*: label for snapshots *within* a single test
  run (e.g. `snap_0`, `snap_1`, ... in `felix/k8sfv`'s memory-leak
  scenario).  Use this for in-test time series; use `iter` for repeated
  whole-test runs.  All three can coexist: a test running three steady
  iterations of twenty heap snapshots would have `iter ∈ {1,2,3}`,
  `phase = "steady"`, `test_step ∈ {"snap_0", ..., "snap_19"}`.

## Index naming convention

Indices are named `<family>_<period-suffix>`, where:

- **`<family>`** is `benchmark_data_<test>` (e.g. `benchmark_data_neutron_resync`).
- **`<period-suffix>`** is either `YYYY` (yearly) or `YYYY-MM` (monthly).
  **Don't use daily.**

`send-perf-results` writes to a yearly suffix.  For most monorepo perf
tests, **yearly is the right default** -- it minimises shard count, keeps
cluster-state overhead lowest, and the data volumes leave plenty of
headroom.  Pick monthly only if:

- **High document volume.**  A year's worth could plausibly exceed 10 GB in
  a single index.  ES wants primary shards in the 10–50 GB range; at ~500
  bytes per doc a yearly index can fit ~20M docs comfortably.  None of our
  current tests come close.
- **Sub-yearly retention.**  Yearly forces you to wait until the year rolls
  over before shedding any data.
- **Frequent schema evolution.**  Monthly gives you a natural reset point.

In Kibana, create a single index pattern per family with a wildcard
(`benchmark_data_<test>_*`).  That picks up both yearly and monthly so you
can switch granularity later without losing continuity.

**Why not daily?**  Daily indices over-fragment intrinsically low-volume
perf data: hundreds of nearly-empty shards waste heap, cluster state
balloons, query fan-out gets expensive, and dynamic mapping inference (see
[ES schema gotchas](#es-schema-gotchas)) gets 365 chances per year to drift
instead of 1.  Tiger-bench's existing indices predate this convention and
can stay where they are; new test families should follow it.

## Adding a new index family

1. Pick a family name following `benchmark_data_<test>`.
2. Add `hack/perf/index-templates/<family>.json` covering at least the
   metadata fields plus your scenario-specific numeric metrics.  See the
   [starter template](#starter-index-template) below.
3. Have your test write to `artifacts/perf/<family>/*.json`.
4. Add a `send-perf-results` invocation to the end of the producing
   Semaphore job (if not already there from a previous family).
5. After the first CI run, [verify the data landed](#verifying-data-landed).

### Starter index template

A minimal template covering the metadata fields and a `total_ms` metric.
Drop it at `hack/perf/index-templates/benchmark_data_<test>.json` and add
your scenario-specific numeric fields alongside `total_ms`:

```json
{
  "index_patterns": ["benchmark_data_<test>_*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":   {"type": "date"},
        "git_commit":   {"type": "keyword"},
        "git_branch":   {"type": "keyword"},
        "ci_run_id":    {"type": "keyword"},
        "code_version": {"type": "keyword"},
        "pr_number":    {"type": "keyword"},
        "test_name":    {"type": "keyword"},
        "dataplane":    {"type": "keyword"},
        "encap":        {"type": "keyword"},
        "k8s_version":  {"type": "keyword"},
        "cloud":        {"type": "keyword"},
        "node_type":    {"type": "keyword"},
        "env":          {"type": "keyword"},
        "phase":        {"type": "keyword"},
        "test_step":    {"type": "keyword"},
        "iter":         {"type": "integer"},
        "ok":           {"type": "boolean"},
        "error":        {"type": "keyword"},
        "total_ms":     {"type": "double"}
      }
    }
  }
}
```

Replace `<test>` in `index_patterns` with your family suffix.  Pin every
numeric metric you care about as `double` if there's any chance it'll go
fractional (see "Numeric type widening" below).

## ES schema gotchas

- **Dynamic mapping inference.**  ES infers field types from the *first*
  document indexed into each new index.  If the first doc in one period
  has `error: null` and the first doc in the next has `error: "timeout"`,
  you get mapping inconsistency across the index pattern and Kibana shows
  "conflict" warnings.  **Fix:** rely on the index template
  (`send-perf-results` applies them on every invocation, so a template
  change auto-propagates).  Even pinning a handful of known fields
  prevents most surprises.
- **`text` vs `keyword`.**  ES's default dynamic mapping maps strings as
  `text` (full-text searchable, **not aggregatable**) with a `.keyword`
  subfield.  To filter or group by `git_branch` in Kibana, you'd then have
  to use `git_branch.keyword`.  Less awkward to pin string fields as
  `keyword` in the template.
- **Field count limit.**  ES caps an index at 1000 fields by default.  You
  won't hit this with a flat doc; you can hit it surprisingly fast with a
  deeply-nested one.
- **Numeric type widening.**  If your first doc has `total_ms: 100` (mapped
  as `long`) and a later doc has `total_ms: 100.5`, the later push fails
  the mapping.  Pin numeric metrics as `double` in the template if there's
  any chance they'll go fractional.

## Kibana visualisation gotchas

- **Lens, the default visualiser, doesn't chart `nested`-typed fields.**
  TSVB and Vega can, but you'd rather not be writing Vega.  Avoid nested
  fields.
- **Time field required.**  Kibana index patterns need a date field to
  enable time-series views.  Use `@timestamp`.
- **Index pattern wildcards.**  One per test family:
  `benchmark_data_neutron_resync_*` covers yearly and monthly suffixes.

## Patterns for tricky cases

### Multiple iterations per run (cold + N steady)

Push one document per iteration.  Distinguish via `phase` and `iter`:

```
{ phase: "cold",   iter: 0, total_ms: 6798, ... }
{ phase: "steady", iter: 1, total_ms: 4769, ... }
{ phase: "steady", iter: 2, total_ms: 4730, ... }
{ phase: "steady", iter: 3, total_ms: 4672, ... }
```

In Kibana, chart median of `total_ms` filtered by `phase: "steady"`, or
compare cold vs steady side-by-side.

### Time-series within a single run

For tests like `felix/k8sfv`'s memory-leak scenario -- heap snapshots
throughout a long-running test -- push one doc per snapshot with a
`test_step` label:

```
{ test_step: "snap_0",  heap_alloc_bytes: 12345678, ... }
{ test_step: "snap_1",  heap_alloc_bytes: 13456789, ... }
...
{ test_step: "snap_19", heap_alloc_bytes: 25678901, ... }
```

Each doc still gets the full metadata (commit, branch, ci_run_id) -- those
are repeated across docs in the run.  ES handles this fine and Kibana lets
you chart `heap_alloc_bytes` over `test_step`, with `git_commit` as a
series breakdown for cross-run comparison.

### Pass/fail alongside continuous metrics

Just include `ok: true|false` (and optional `error: "<message>"`) on the
same doc as the timing.  Kibana can chart failure rate per scenario as a
separate visualisation in the same dashboard.

### Test failure or partial results

If your test crashes partway through:

- **Partial metrics available**: write the file you have with `ok: false`
  and `error: "<reason>"`.  A "test failed at scale=1000" data point is
  itself useful trend information.
- **Nothing usable** (e.g. infra failed before the test started): don't
  write a file.  A doc with `null` everywhere just creates noise -- use
  the CI log for the failure record instead.

## Operational hygiene

- **Don't push from local dev runs.**  Most developers won't have Lens
  creds anyway -- `send-perf-results` already skips silently when
  `ELASTICSEARCH_URL` is unset.  If you *do* push locally (e.g. for
  testing the tool itself), the injected `env: dev` lets dashboards
  filter dev runs out.
- **Index retention.**  Check with the Lens cluster owners whether ILM
  (Index Lifecycle Management) is configured for `benchmark_data_*`.  If
  not, indices accumulate forever.  Worth setting up an ILM policy that
  rolls older indices to a cheaper tier.
- **Schema evolution.**  If you need to change the *meaning* of a field,
  don't try to patch the existing family in place -- start a new one
  (`benchmark_data_neutron_resync_v2_*`) and update dashboards.  Fighting
  type drift across periods is more pain than starting fresh.

## Verifying data landed

After your first CI run, confirm the doc made it into ES before going
further.  From Kibana → **Dev Tools**:

```
GET benchmark_data_<test>_*/_search
{
  "size": 5,
  "sort": [{"@timestamp": "desc"}]
}
```

You should see your most recent docs with the expected fields and types.
If a field shows up as `text` when you wanted `keyword`, your index
template didn't take effect -- check that the template's `index_patterns`
matches your actual index name.

From the shell:

```bash
curl -s "$ELASTICSEARCH_URL/benchmark_data_<test>_*/_search?size=5&sort=@timestamp:desc" \
  -H "Authorization: ApiKey $ELASTICSEARCH_KEY" | jq '.hits.hits'
```

To see the inferred mapping for a specific index:

```
GET benchmark_data_<test>_2026/_mapping
```

## Next steps once you've pushed data

1. **Create a Kibana index pattern.**  Stack Management → Index Patterns →
   Create.  Pattern: `benchmark_data_<your_test>_*`.  Time field: `@timestamp`.
2. **Build a starter Lens visualisation.**  Drag your primary metric onto
   Y, `@timestamp` onto X.  Break out by `dataplane` or `git_branch` as a
   series.
3. **Save it to a dashboard.**  Add filters for `env: ci` and any baseline
   scenario settings.
4. **Share the dashboard URL.**  Add it next to your test's documentation
   so others can see how the test has trended.

## Local development

To test the tool itself against a local files-only flow:

```sh
go run ./hack/perf/cmd/send-perf-results --dry-run --dir /tmp/some/perf
```

`--dry-run` prints what would be POSTed without contacting ES.
