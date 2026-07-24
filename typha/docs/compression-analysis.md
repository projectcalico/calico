# Zstd vs Snappy Compression for Typha Syncproto

## Summary

Zstd compresses Typha snapshots to roughly **half the size** of snappy, even at
its fastest setting (`zstd.SpeedFastest`). The compression speed trade-off is
acceptable because Typha pre-computes and caches snapshots server-side, making
transfer size the dominant factor for client bootstrap performance.

## Measured on Real Typha Data

The benchmark in
[`typha/pkg/syncserver/compression_bench_test.go`](../pkg/syncserver/compression_bench_test.go)
compresses gob-encoded `WorkloadEndpoint`, `GlobalConfig`, and `HostIP` KVs --
the same data types Typha sends to Felix clients via the sync protocol.

### Compression Ratio

| Scenario | Raw (gob) | Snappy | Zstd (SpeedFastest) | Zstd savings vs snappy |
|---|---|---|---|---|
| **Small** (160 KVs) | 100.3 KB | 58.2 KB (1.72:1) | 29.7 KB (3.37:1) | **48.9%** |
| **Medium** (1,250 KVs) | 692.2 KB | 272.9 KB (2.54:1) | 132.9 KB (5.21:1) | **51.3%** |
| **Large** (10,700 KVs) | 5,438.4 KB | 1,170.6 KB (4.65:1) | 561.3 KB (9.69:1) | **52.1%** |

The advantage grows with scale. At 10K pods, zstd achieves a **9.69:1** ratio
versus snappy's **4.65:1**.

### Throughput (Go Benchmarks, 1,000-pod snapshot)

| Operation | Snappy | Zstd | Ratio |
|---|---|---|---|
| **Compression** | 2,130 MB/s | 328 MB/s | Snappy ~6.5x faster |
| **Decompression** | 1,175 MB/s | 374 MB/s | Snappy ~3.1x faster |

Measured with klauspost/compress v1.19.0 on an Intel Core i7-11850H @ 2.50GHz,
using `go test -bench -benchtime=2s -count=6` summarized by `benchstat`
(variation within ±7% for all benchmarks).

### Allocations (per operation, 1,000-pod snapshot)

| Operation | Snappy | Zstd |
|---|---|---|
| **Compression** | 292 KB / 7 allocs | 9,359 KB / 100 allocs |
| **Decompression** | 1,160 KB / 26 allocs | 6,925 KB / 87 allocs |

Zstd uses more memory per operation due to its larger internal state (encoder
tables, entropy buffers). This is acceptable because snapshots are compressed
once and cached server-side, and decompression happens once per client bootstrap.

## Why the Ratio Difference Is So Large on Typha Data

Typha's gob-encoded data has a lot of repetitive structure: repeated field names
like `"kubernetes-topology-label"`, repeated namespace prefixes, repeated model
keys, gob type headers, etc. Zstd uses a larger match window (up to 128 KB
default vs snappy's ~64 KB blocks) and more sophisticated entropy coding (Finite
State Entropy / Huffman), which exploits these repetitions much more effectively
than snappy's simple LZ77.

## Why the Speed Trade-off Is Acceptable

Snappy is faster at both compression and decompression, but this matters less
for Typha because:

- **Snapshots are pre-computed and cached** (`snap_precalc.go`). The server
  builds the compressed snapshot once and sends it to many clients. Compression
  speed is a one-time cost amortized over all connections.

- **Transfer size is what matters most.** Typha sends snapshots over TCP to
  Felix clients. A 52% smaller snapshot means ~52% less data on the wire,
  which directly translates to faster client bootstrap time in large clusters.

- **Decompression speed is plenty fast.** At ~374 MB/s, zstd decompresses a
  10K-pod snapshot (~561 KB compressed -> 5.4 MB raw) in under 20 ms. This is
  negligible compared to network RTT.

## Real-World Impact

For a large cluster with 10K pods, the snapshot drops from **1.17 MB (snappy)
to 561 KB (zstd)**. When Typha is serving dozens or hundreds of Felix clients
simultaneously during a rolling restart, this translates to:

- **Significant bandwidth savings** on the Typha server
- **Faster client catch-up** during bootstrap
- **Less pressure on the TCP send buffer** and reduced memory usage

## Why Pure Go (klauspost) Instead of the Faster Cgo libzstd

We also compared klauspost's pure-Go zstd against the cgo binding for the
reference C library (`github.com/DataDog/zstd` v1.5.7, bundled libzstd),
using the same 1,000-pod snapshot data on the same machine. The two produce
interchangeable output: each decodes the other's streams.

| Metric | Pure Go (SpeedFastest) | Cgo libzstd (level 1) |
|---|---|---|
| **Compression** | 307 MB/s | 948 MB/s (~3.1x faster) |
| **Decompression** | 311 MB/s | 928 MB/s (~3.0x faster) |
| **Compressed size** | 28,932 B | 27,441 B (~5% smaller) |
| **Go-heap allocations, compress** | 9.1 MB / 100 allocs | 0.5 MB / 7 allocs (*not comparable*) |
| **Go-heap allocations, decompress** | 6.1 MB / 44 allocs | 1.0 MB / 28 allocs (*not comparable*) |

The allocation rows only count Go-heap memory, which is all that Go's
benchmark tooling can see. libzstd allocates its working memory (window,
match tables) with C malloc, outside the Go heap, so the cgo numbers look
artificially small. Treat them as "Go-visible overhead", not as total
memory use.

Cgo libzstd wins the microbenchmark clearly. We chose the pure-Go
implementation anyway:

- **Compression is not the bottleneck.** Snapshots are compressed at most
  once per second per (syncer, algorithm) and served from cache: ~18 ms
  pure-Go vs ~6 ms cgo for a 10K-pod snapshot. Clients decompress one
  snapshot per connection. Both are noise next to network transfer, so the
  3x speed advantage buys nothing in practice.
- **Build and maintenance cost.** Calico ships amd64, arm64, ppc64le, and
  s390x images plus a Windows Felix client, which must decode zstd. A cgo
  dependency needs a C cross-toolchain for every target and separate CVE
  tracking for the vendored C library. klauspost/compress is a normal Go
  dependency.
- **Runtime behavior.** Cgo calls pin OS threads and add per-call overhead,
  which works against the per-connection delta path (many connections,
  small frequently-flushed writes).
- **Decoder correctness gaps in the cgo wrapper.** The DataDog wrapper's
  decoder skips checksums, omits some error checks, and mishandles
  concatenated streams. Our protocol depends on concatenated frames: the
  client's reused decoder reads the cached snapshot frame and the
  per-connection delta frames back to back on one connection.

The cgo comparison benchmark is not checked in because it would add the cgo
dependency to the module; it is a ~150-line test that reuses
`generateBenchPod` data with `github.com/DataDog/zstd` writers/readers.

## Reproducing the Results

```bash
# Compression ratio comparison across cluster sizes (skipped by default)
COMPRESSION_ANALYSIS=true go test -v -run TestCompressionComparison ./typha/pkg/syncserver/

# Go benchmarks for throughput measurement (summarize with benchstat)
go test -bench="Benchmark(Snappy|Zstd)" -benchmem -count=6 -benchtime=2s -run=NONE ./typha/pkg/syncserver/

# Round-trip correctness verification
go test -v -run TestCompressionRoundTrip ./typha/pkg/syncserver/
```
