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
| **Small** (160 KVs) | 100.3 KB | 58.1 KB (1.72:1) | 29.7 KB (3.37:1) | **48.9%** |
| **Medium** (1,250 KVs) | 692.0 KB | 272.7 KB (2.54:1) | 132.9 KB (5.21:1) | **51.3%** |
| **Large** (10,700 KVs) | 5,437.8 KB | 1,170.0 KB (4.65:1) | 561.3 KB (9.69:1) | **52.0%** |

The advantage grows with scale. At 10K pods, zstd achieves a **9.69:1** ratio
versus snappy's **4.65:1**.

### Throughput (Go Benchmarks, 1,000-pod snapshot)

| Operation | Snappy | Zstd | Ratio |
|---|---|---|---|
| **Compression** | 1,920 MB/s | 354 MB/s | Snappy ~5.4x faster |
| **Decompression** | 543 MB/s | 302 MB/s | Snappy ~1.8x faster |

Measured on an Intel Core i7-11850H @ 2.50GHz using `go test -bench -benchtime=3s`.

### Allocations (per operation, 1,000-pod snapshot)

| Operation | Snappy | Zstd |
|---|---|---|
| **Compression** | 299 KB / 7 allocs | 9,584 KB / 100 allocs |
| **Decompression** | 2,685 KB / 28 allocs | 8,593 KB / 92 allocs |

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

- **Decompression speed is plenty fast.** At 302 MB/s, zstd decompresses a
  10K-pod snapshot (~561 KB compressed -> 5.4 MB raw) in under 20 ms. This is
  negligible compared to network RTT.

## Real-World Impact

For a large cluster with 10K pods, the snapshot drops from **1.17 MB (snappy)
to 561 KB (zstd)**. When Typha is serving dozens or hundreds of Felix clients
simultaneously during a rolling restart, this translates to:

- **Significant bandwidth savings** on the Typha server
- **Faster client catch-up** during bootstrap
- **Less pressure on the TCP send buffer** and reduced memory usage

## Reproducing the Results

```bash
# Compression ratio comparison across cluster sizes
go test -v -run TestCompressionComparison ./typha/pkg/syncserver/

# Go benchmarks for throughput measurement
go test -bench="Benchmark(Snappy|Zstd)" -benchmem -count=1 -benchtime=3s ./typha/pkg/syncserver/

# Round-trip correctness verification
go test -v -run TestCompressionRoundTrip ./typha/pkg/syncserver/
```
