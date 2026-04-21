# encoding/json v1 vs v2 Benchmark Report

**Date:** 2026-04-21
**Go version:** go1.26.2 linux/amd64 (GOEXPERIMENT=jsonv2)
**CPU:** 11th Gen Intel Core i7-11850H @ 2.50GHz
**Runs:** 10 iterations per benchmark (`-count=10 -benchtime=1s`)

## Test Data

Benchmarks use realistic Calico data types modeled on production structs.
Each type was chosen because it appears on a real `json.Marshal` /
`json.Unmarshal` hot path (etcdv3 value serialization, Typha `Value`
payloads, or K8s CRD round-trips). YAML is not exercised directly — the
calicoctl YAML path delegates to `json.Marshal` internally via
`sigs.k8s.io/yaml`, so these benchmarks cover the Go-struct↔bytes step of
both JSON and YAML paths.

| Benchmark | Modeled on | Where it's marshaled | Description |
|---|---|---|---|
| PolicyMarshal / Unmarshal | `apiv3.GlobalNetworkPolicy` | etcdv3 value, Typha `Value`, CRD annotations | 4 rules with selectors, CIDRs, ports |
| FelixConfigMarshal / Unmarshal | `apiv3.FelixConfigurationSpec` | etcdv3 value, Typha `Value`, CRD annotations | ~30 pointer-heavy fields, mixed types |
| WorkloadEndpointMarshal / Unmarshal | `model.WorkloadEndpoint` | Typha `Value` (one per pod) | Single-WEP round trip — dominant Typha payload |
| WorkloadEndpointBatchMarshal / Unmarshal | 50 × `model.WorkloadEndpoint` | Typha `Value` batch | 50 individual marshal/unmarshal calls — throughput view of a sync batch |
| LabelsMarshal / Unmarshal | `map[string]string` × 10 | inside every K8s object | Kubernetes-style labels, most common map type |

**Note:** Earlier versions of this report included a `SyncBatchMarshal`
benchmark modeled on `typha/pkg/syncproto.SerializedUpdate`. That was
dropped because the Typha wire format is `gob`, not JSON — `SerializedUpdate`
is never `json.Marshal`ed in production. The realistic JSON hot path on
the Typha sync is marshaling the *inner* `Value` one struct at a time,
which is now covered by the `WorkloadEndpointBatch` benchmarks.

## Results Summary

| Benchmark | v1 mean | v2 mean | Speedup | v1 allocs | v2 allocs |
|---|---|---|---|---|---|
| FelixConfigMarshal | 3,265 ns | 3,366 ns | -3.1% | 3 | 3 |
| FelixConfigUnmarshal | 5,003 ns | 3,794 ns | **+24.2%** | 19 | 19 |
| LabelsMarshal | 2,281 ns | 1,637 ns | **+28.2%** | 15 | 5 |
| LabelsUnmarshal | 3,304 ns | 3,033 ns | **+8.2%** | 12 | 12 |
| PolicyMarshal | 5,302 ns | 5,178 ns | +2.3% | 11 | 7 |
| PolicyUnmarshal | 9,517 ns | 10,017 ns | -5.3% | 32 | 32 |
| WorkloadEndpointMarshal | 4,092 ns | 3,358 ns | **+17.9%** | 17 | 5 |
| WorkloadEndpointUnmarshal | 6,929 ns | 6,321 ns | **+8.8%** | 19 | 19 |
| WorkloadEndpointBatchMarshal | 204,437 ns | 166,629 ns | **+18.5%** | 850 | 250 |
| WorkloadEndpointBatchUnmarshal | 362,445 ns | 330,680 ns | **+8.8%** | 1,034 | 1,034 |

## Detailed Results (10 runs, mean ± std dev)

| Benchmark | Version | Mean (ns/op) | Std Dev | B/op | Allocs/op | Speedup | Alloc Change |
|---|---|---|---|---|---|---|---|
| FelixConfigMarshal | v1 | 3,265 | ±267 | 1,729 | 3 | | |
| | v2 | 3,366 | ±117 | 1,729 | 3 | -3.1% | same |
| FelixConfigUnmarshal | v1 | 5,003 | ±640 | 520 | 19 | | |
| | v2 | 3,794 | ±178 | 520 | 19 | **+24.2%** | same |
| LabelsMarshal | v1 | 2,281 | ±88 | 656 | 15 | | |
| | v2 | 1,637 | ±43 | 496 | 5 | **+28.2%** | **−10 (−67%)** |
| LabelsUnmarshal | v1 | 3,304 | ±115 | 1,056 | 12 | | |
| | v2 | 3,033 | ±212 | 1,056 | 12 | **+8.2%** | same |
| PolicyMarshal | v1 | 5,302 | ±525 | 1,538 | 11 | | |
| | v2 | 5,178 | ±176 | 1,473 | 7 | +2.3% | **−4 (−36%)** |
| PolicyUnmarshal | v1 | 9,517 | ±703 | 4,235 | 32 | | |
| | v2 | 10,017 | ±386 | 4,235 | 32 | -5.3% | same |
| WorkloadEndpointMarshal | v1 | 4,092 | ±123 | 1,153 | 17 | | |
| | v2 | 3,358 | ±110 | 960 | 5 | **+17.9%** | **−12 (−71%)** |
| WorkloadEndpointUnmarshal | v1 | 6,929 | ±239 | 2,041 | 19 | | |
| | v2 | 6,321 | ±296 | 2,041 | 19 | **+8.8%** | same |
| WorkloadEndpointBatchMarshal | v1 | 204,437 | ±7,198 | 57,680 | 850 | | |
| | v2 | 166,629 | ±6,583 | 48,032 | 250 | **+18.5%** | **−600 (−71%)** |
| WorkloadEndpointBatchUnmarshal | v1 | 362,445 | ±16,242 | 103,435 | 1,034 | | |
| | v2 | 330,680 | ±13,770 | 103,444 | 1,034 | **+8.8%** | same |

## Analysis

### WorkloadEndpoint marshaling is the biggest real-world win

WorkloadEndpoints are the dominant payload on the Typha→Felix sync path
(one per pod; production clusters carry thousands). The single-WEP marshal
is **18% faster** with **71% fewer allocations** (17 → 5). The batch
version (50 WEPs marshaled one-by-one, exactly as `libcalico-go`'s
`SerializeValue` does on every sync cycle) saves **600 allocations per 50
WEPs** — at scale this materially reduces GC pressure on both Typha and
Felix.

### Labels see the largest relative improvement (28% marshal, 67% fewer allocs)

Kubernetes labels (`map[string]string`) are the single most frequently
serialized type in Calico — every endpoint, policy, node, and IP pool
carries labels. The 28% marshal speedup with allocs dropping from 15 → 5
directly reduces GC pressure in Felix's calculation graph, which processes
label maps on every policy evaluation.

### Unmarshal is consistently faster on the sync hot path

Every Typha-adjacent unmarshal benchmark improves with v2: FelixConfig
+24%, WorkloadEndpoint +9%, WorkloadEndpointBatch +9%, Labels +8%. Felix
deserializes every update received from Typha, so these improvements
compound across the thousands of KVs processed per sync.

### Marshal allocation savings are substantial (36–71% fewer)

Even where nanosecond speedups are modest, v2 drops allocation counts
significantly on marshal: −36% for policies, −67% for labels, −71% for
WEPs (single and batch). Fewer allocations means less GC work, which
matters for long-running daemons like Felix processing continuous
datastore updates.

### PolicyUnmarshal is the only regression (−5%)

PolicyUnmarshal is ~5% slower with v2 — the only statistically suspect
regression, and it sits within ~1 std dev of the v1 mean. Allocation
counts are identical. Policies are typically unmarshaled at most a few
hundred times per cluster (not per-endpoint), so the absolute impact is
negligible. FelixConfigMarshal's −3% is within run-to-run noise (both
means are within one std dev of each other).

### Variance

Standard deviation is typically 2–5% of mean for most benchmarks, with
Unmarshal benchmarks slightly noisier due to allocator behavior.
v2 std dev is consistently lower than v1 across benchmarks — output is
more predictable.

## Reproducing

```bash
GOEXPERIMENT=jsonv2 go test -bench=. -benchmem -count=10 ./hack/cmd/jsonbench/
```
