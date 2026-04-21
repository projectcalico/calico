# encoding/json v1 vs v2 Benchmark Report

**Date:** 2026-04-20
**Go version:** go1.26.2 linux/amd64 (GOEXPERIMENT=jsonv2)
**CPU:** 11th Gen Intel Core i7-11850H @ 2.50GHz
**Runs:** 10 iterations per benchmark

## Test Data

Benchmarks use realistic Calico data types modeled on production structs:

| Benchmark | Modeled on | Description |
|---|---|---|
| PolicyMarshal/Unmarshal | `GlobalNetworkPolicy` | 4 rules with selectors, CIDRs, ports. Policy hot path. |
| FelixConfigMarshal/Unmarshal | `FelixConfigurationSpec` | ~30 pointer-heavy fields with mixed types. Config sync. |
| SyncBatchMarshal/Unmarshal | `SerializedUpdate` x50 | Typha-Felix wire protocol. High frequency sync path. |
| LabelsMarshal/Unmarshal | `map[string]string` x10 | Kubernetes-style labels. Most common map type. |

## Results Summary

| Benchmark | v1 mean | v2 mean | Speedup | v1 allocs | v2 allocs |
|---|---|---|---|---|---|
| FelixConfigMarshal | 3,294 ns | 3,540 ns | -7.5% | 3 | 3 |
| FelixConfigUnmarshal | 4,432 ns | 3,661 ns | **+17.4%** | 19 | 19 |
| LabelsMarshal | 2,360 ns | 1,660 ns | **+29.6%** | 15 | 5 |
| LabelsUnmarshal | 3,305 ns | 2,925 ns | **+11.5%** | 12 | 12 |
| PolicyMarshal | 5,328 ns | 5,218 ns | ~same | 11 | 7 |
| PolicyUnmarshal | 10,725 ns | 9,693 ns | **+9.6%** | 32 | 32 |
| SyncBatchMarshal | 39,784 ns | 40,251 ns | ~same | 103 | 103 |
| SyncBatchUnmarshal | 71,807 ns | 59,987 ns | **+16.5%** | 208 | 158 |

## Detailed Results (10 runs, mean +/- std dev)

| Benchmark | Version | Mean (ns/op) | Std Dev | B/op | Allocs/op | Speedup | Alloc Change |
|---|---|---|---|---|---|---|---|
| FelixConfigMarshal | v1 | 3,294 | +-136 | 1,729 | 3 | | |
| | v2 | 3,540 | +-151 | 1,729 | 3 | -7.5% | same |
| FelixConfigUnmarshal | v1 | 4,432 | +-138 | 520 | 19 | | |
| | v2 | 3,661 | +-56 | 520 | 19 | **+17.4%** | same |
| LabelsMarshal | v1 | 2,360 | +-90 | 656 | 15 | | |
| | v2 | 1,660 | +-58 | 496 | 5 | **+29.6%** | **-10 (-67%)** |
| LabelsUnmarshal | v1 | 3,305 | +-77 | 1,056 | 12 | | |
| | v2 | 2,925 | +-99 | 1,056 | 12 | **+11.5%** | same |
| PolicyMarshal | v1 | 5,328 | +-492 | 1,538 | 11 | | |
| | v2 | 5,218 | +-106 | 1,473 | 7 | +2.1% | **-4 (-36%)** |
| PolicyUnmarshal | v1 | 10,725 | +-458 | 4,235 | 32 | | |
| | v2 | 9,693 | +-507 | 4,235 | 32 | **+9.6%** | same |
| SyncBatchMarshal | v1 | 39,784 | +-2,155 | 17,253 | 103 | | |
| | v2 | 40,251 | +-1,793 | 17,251 | 103 | -1.2% | same |
| SyncBatchUnmarshal | v1 | 71,807 | +-2,022 | 21,736 | 208 | | |
| | v2 | 59,987 | +-1,500 | 21,335 | 158 | **+16.5%** | **-50 (-24%)** |

## Analysis

### Unmarshal is consistently faster (9-17%)

Every unmarshal benchmark is faster with v2. This is the most impactful
improvement for Calico because Felix deserializes all updates received from
Typha. The Typha-Felix sync path (SyncBatchUnmarshal) shows a 16.5%
speedup with 24% fewer allocations — at scale with thousands of updates per
sync cycle, this translates to measurably less CPU time and GC pressure on
every node.

### Labels/maps see the largest improvement (30% faster, 67% fewer allocs)

Kubernetes labels (`map[string]string`) are the single most frequently
serialized type in Calico — every endpoint, policy, node, and IP pool
carries labels. The 30% marshal speedup with 67% fewer allocations (15 -> 5)
directly reduces GC pressure in Felix's calculation graph, which processes
label maps on every policy evaluation.

### Marshal is roughly equivalent, with fewer allocations

Marshal performance is within noise for most types, but allocation counts
drop significantly: 36% fewer for policies, 67% fewer for labels. Fewer
allocations means less GC work, which matters in a long-running daemon like
Felix that processes continuous datastore updates.

### FelixConfig marshal is slightly slower (-7.5%)

The only regression is FelixConfigurationSpec marshal, a pointer-heavy struct
with ~30 `omitempty` fields. v2's richer omitempty semantics add a small
overhead for checking whether each pointer's JSON encoding is "empty." This
is a low-frequency operation (config syncs happen rarely) so the impact is
negligible. The corresponding unmarshal is 17% faster, which more than
compensates.

### Variance

Standard deviation is typically 2-5% of mean for most benchmarks, with
PolicyMarshal v1 showing the highest variance at ~9%. Results are stable
and p-values from `benchstat` confirm all flagged speedups are statistically
significant (p < 0.01).

### Comparison with Go 1.26.1 baseline

Results are consistent with the original Go 1.26.1 measurements — qualitative
conclusions are unchanged across Go versions:

| Benchmark              | Go 1.26.1 | Go 1.26.2 |
|------------------------|-----------|-----------|
| FelixConfigMarshal     | -5.3%     | -7.5%     |
| FelixConfigUnmarshal   | +15.9%    | +17.4%    |
| LabelsMarshal          | +30.7%    | +29.6%    |
| LabelsUnmarshal        | +10.3%    | +11.5%    |
| PolicyMarshal          | +1.0%     | +2.1%     |
| PolicyUnmarshal        | +9.0%     | +9.6%     |
| SyncBatchMarshal       | +0.9%     | -1.2%     |
| SyncBatchUnmarshal     | +18.6%    | +16.5%    |

The FelixConfigMarshal regression deepened slightly (-5% → -7.5%), still
well within "negligible for a low-frequency operation." All other benchmarks
are within ±3 percentage points of the original, well inside run-to-run
variance. Allocation counts are byte-identical to the 1.26.1 run.

## Reproducing

```bash
cd lib/std
GOEXPERIMENT=jsonv2 go test -bench=. -benchmem -count=10 ./jsonbench/
```
