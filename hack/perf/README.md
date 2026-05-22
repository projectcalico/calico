# Cross-monorepo performance-result publishing

This directory is the canonical home for plumbing that gets perf-test
measurements into the Lens Elasticsearch cluster, where they can be tracked
over time.  See `~/perf.md` (and tiger-bench's `pkg/elasticsearch` for prior
art) for the cluster's conventions and operational expectations.

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
   single ES document containing **only the scenario-specific scalars** —
   scale dimensions, metrics, test_name, and so on.  CI metadata
   (`git_commit`, `ci_run_id`, etc.) is NOT the producer's job.  See
   "Schema" below for what counts as scenario-specific.

2. Arrange for `send-perf-results` to run once at the end of the producing
   Semaphore job.  The simplest pattern is to add a line near the end of
   the job's commands:

   ```sh
   go run ./hack/perf/cmd/send-perf-results --dir artifacts/perf
   ```

   (or invoke a pre-built binary).  Calling it exactly once per job is the
   only operational discipline required — see "Idempotency" below.

`artifacts/perf/` lives under the existing `artifacts/` upload, so the
per-measurement JSON files are also automatically captured as Semaphore
artifacts — useful for post-mortem when a number looks off.

## What `send-perf-results` does

On each invocation, in order:

1. **Apply index templates.**  For every `hack/perf/index-templates/<family>.json`,
   PUT it to `/_index_template/<family>` in ES.  Idempotent upsert; committing
   a template change propagates automatically on the next CI run.
2. **Walk `artifacts/perf/<family>/*.json`** for every `<family>` subdirectory.
3. **Augment each doc** with CI metadata (`@timestamp`, `git_commit`,
   `git_branch`, `code_version`, `ci_run_id`, `pr_number`, `env`) unless the
   producer already supplied that field — producer values win.  Picked up
   from `SEMAPHORE_GIT_SHA`, `SEMAPHORE_GIT_BRANCH`, `SEMAPHORE_JOB_ID`,
   `SEMAPHORE_GIT_PR_NUMBER`.
4. **POST to `<family>_<UTC year>/_doc`.**  The year suffix is computed at
   send time; producer side stays date-free.  ES auto-creates the dated
   index on first write using the template applied in step 1.
5. Exit 0.

Per `perf.md`, "Lens is observability, not a critical path": the tool only
returns non-zero in genuinely unrecoverable cases.  Missing credentials,
unreachable ES, malformed JSON, mapping conflicts — all log a warning and
continue.  A `--require-creds` flag flips the missing-creds case to a hard
failure, for places that want a strict gate on the publish step.

## Idempotency

The tool sends **every JSON file it sees** on each invocation.  It does not
move sent files aside, hash content, or otherwise dedupe.  This is by design
— each Semaphore job has its own fresh filesystem, so within-job idempotency
isn't strictly required.

The single operational rule: **call `send-perf-results` exactly once per
job, at the end, after all producers in that job have written their files.**
A second invocation in the same job would resend everything and create
duplicate ES documents (differing only in injected `@timestamp`).

## Schema

Per `perf.md`'s "What makes a good datapoint": one measurement per document,
flat scalars only, no nested objects or arrays-of-objects.  Producers should
include:

- Their own `test_name` (a stable string identifying the scenario family).
- Scenario-specific scale dimensions (e.g. `scale_ports`, `scale_policies`).
- The measured metrics, flattened (e.g. `endpoints_total_ms`, not
  `endpoints.total_ms`).
- `phase` / `iter` / `test_step` keywords if the doc is one of several
  related sub-measurements (cold vs steady, repeated iterations,
  in-test time-series snapshots).
- `ok: bool` and `error: string` if the test can partially succeed.

The tool fills in the CI metadata fields; producers should not duplicate
those.

## Adding a new index family

1. Pick a family name following `benchmark_data_<test>` from `perf.md`.
2. Add `hack/perf/index-templates/<family>.json` covering at least the
   metadata fields plus your scenario-specific numeric metrics.  Pin every
   numeric metric as `double` if there's any chance it'll go fractional
   (per `perf.md`'s "Numeric type widening" note).
3. Have your test write to `artifacts/perf/<family>/*.json`.
4. Add `go run ./hack/perf/cmd/send-perf-results` (or equivalent binary
   call) to the end of the producing Semaphore job.
5. After the first CI run, verify the data landed with the Kibana dev-tools
   query in `perf.md`.

## Local development

Local runs naturally skip the push because `ELASTICSEARCH_URL` is unset,
and the injected `env` field is `dev` rather than `ci` (so any future
accidental dev-environment push is filterable out of trend dashboards).

To test the tool against a local files-only flow:

```sh
go run ./hack/perf/cmd/send-perf-results --dry-run --dir /tmp/some/perf
```

`--dry-run` prints what would be POSTed without contacting ES.
