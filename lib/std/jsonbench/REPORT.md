# encoding/json v1 vs v2 Benchmark Report

**Date:** 2026-03-30
**Go version:** go1.26.1 linux/amd64 (GOEXPERIMENT=jsonv2)
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
| FelixConfigMarshal | 2,710 ns | 2,853 ns | -5.3% | 3 | 3 |
| FelixConfigUnmarshal | 4,701 ns | 3,953 ns | **+15.9%** | 19 | 19 |
| LabelsMarshal | 2,362 ns | 1,636 ns | **+30.7%** | 15 | 5 |
| LabelsUnmarshal | 3,143 ns | 2,819 ns | **+10.3%** | 12 | 12 |
| PolicyMarshal | 5,194 ns | 5,143 ns | ~same | 11 | 7 |
| PolicyUnmarshal | 9,225 ns | 8,390 ns | **+9.0%** | 32 | 32 |
| SyncBatchMarshal | 35,257 ns | 34,940 ns | ~same | 103 | 103 |
| SyncBatchUnmarshal | 69,217 ns | 56,360 ns | **+18.6%** | 208 | 158 |

## Detailed Results (10 runs, mean +/- std dev)

| Benchmark | Version | Mean (ns/op) | Std Dev | B/op | Allocs/op | Speedup | Alloc Change |
|---|---|---|---|---|---|---|---|
| FelixConfigMarshal | v1 | 2,710 | +-84 | 1,729 | 3 | | |
| | v2 | 2,853 | +-132 | 1,729 | 3 | -5.3% | same |
| FelixConfigUnmarshal | v1 | 4,701 | +-139 | 520 | 19 | | |
| | v2 | 3,953 | +-60 | 520 | 19 | **+15.9%** | same |
| LabelsMarshal | v1 | 2,362 | +-78 | 656 | 15 | | |
| | v2 | 1,636 | +-92 | 496 | 5 | **+30.7%** | **-10 (-67%)** |
| LabelsUnmarshal | v1 | 3,143 | +-60 | 1,056 | 12 | | |
| | v2 | 2,819 | +-101 | 1,056 | 12 | **+10.3%** | same |
| PolicyMarshal | v1 | 5,194 | +-88 | 1,538 | 11 | | |
| | v2 | 5,143 | +-75 | 1,473 | 7 | +1.0% | **-4 (-36%)** |
| PolicyUnmarshal | v1 | 9,225 | +-216 | 4,235 | 32 | | |
| | v2 | 8,390 | +-460 | 4,235 | 32 | **+9.0%** | same |
| SyncBatchMarshal | v1 | 35,257 | +-962 | 17,251 | 103 | | |
| | v2 | 34,940 | +-930 | 17,250 | 103 | +0.9% | same |
| SyncBatchUnmarshal | v1 | 69,217 | +-1,795 | 21,735 | 208 | | |
| | v2 | 56,360 | +-1,143 | 21,335 | 158 | **+18.6%** | **-50 (-24%)** |

## Analysis

### Unmarshal is consistently faster (9-19%)

Every unmarshal benchmark is faster with v2. This is the most impactful
improvement for Calico because Felix deserializes all updates received from
Typha. The Typha-Felix sync path (SyncBatchUnmarshal) shows an 18.6%
speedup with 24% fewer allocations — at scale with thousands of updates per
sync cycle, this translates to measurably less CPU time and GC pressure on
every node.

### Labels/maps see the largest improvement (31% faster, 67% fewer allocs)

Kubernetes labels (`map[string]string`) are the single most frequently
serialized type in Calico — every endpoint, policy, node, and IP pool
carries labels. The 31% marshal speedup with 67% fewer allocations (15 -> 5)
directly reduces GC pressure in Felix's calculation graph, which processes
label maps on every policy evaluation.

### Marshal is roughly equivalent, with fewer allocations

Marshal performance is within noise for most types, but allocation counts
drop significantly: 36% fewer for policies, 67% fewer for labels. Fewer
allocations means less GC work, which matters in a long-running daemon like
Felix that processes continuous datastore updates.

### FelixConfig marshal is slightly slower (-5.3%)

The only regression is FelixConfigurationSpec marshal, a pointer-heavy struct
with ~30 `omitempty` fields. v2's richer omitempty semantics add a small
overhead for checking whether each pointer's JSON encoding is "empty." This
is a low-frequency operation (config syncs happen rarely) so the impact is
negligible. The corresponding unmarshal is 16% faster, which more than
compensates.

### Standard deviation is low

All measurements show low variance (typically 1-4% of mean), confirming
the results are stable and reproducible.

## Reproducing

```bash
cd lib/std
GOEXPERIMENT=jsonv2 go test -bench=. -benchmem -count=10 ./jsonbench/
```
