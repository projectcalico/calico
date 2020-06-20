---
title: Prometheus statistics
description: Review metrics for the Typha component if you are using Prometheus. 
canonical_url: '/reference/typha/prometheus'
---

Typha can be configured to report a number of metrics through Prometheus.  See the
[configuration reference](configuration) for how to enable metrics reporting.

## Metric reference

#### Typha specific

Typha exports a number of Prometheus metrics.  The current set is as follows.  Since some metrics
are tied to particular implementation choices inside Typha we can't make any hard guarantees that
metrics will persist across releases.  However, we aim not to make any spurious changes to
existing metrics.

| Name          | Description     |
| ------------- | --------------- |
| `typha_breadcrumb_block` | Count of the number of times Typha got the next Breadcrumb after blocking. |
| `typha_breadcrumb_non_block` | typha_breadcrumb_non_block Count of the number of times Typha got the next Breadcrumb without blocking. |
| `typha_breadcrumb_seq_number` | Current (server-local) sequence number; number of snapshot deltas processed. |
| `typha_breadcrumb_size` | Number of KVs recorded in each breadcrumb. |
| `typha_client_latency_secs` | Per-client latency.  I.e. how far behind the current state is each client. |
| `typha_client_snapshot_send_secs` | How long it took to send the initial snapshot to each client. |
| `typha_client_write_latency_secs` | Per-client write.  How long each write call is taking. |
| `typha_connections_accepted` | Total number of connections accepted over time. |
| `typha_connections_active` | Number of open client connections. |
| `typha_connections_dropped` | Total number of connections dropped due to rebalancing. |
| `typha_kvs_per_msg` | Number of KV pairs sent in each message. |
| `typha_log_errors` | Number of errors encountered while logging. |
| `typha_logs_dropped` | Number of logs dropped because the output stream was blocked. |
| `typha_next_breadcrumb_latency_secs` | Time to retrieve next breadcrumb when already behind. |
| `typha_ping_latency` | Round-trip ping latency to client. |
| `typha_updates_skipped` | Total number of updates skipped as duplicates. |
| `typha_updates_total` | Total number of updates received from the Syncer. |

Prometheus metrics are self-documenting, with metrics turned on, `curl` can be used to list the
metrics along with their help text and type information.

```bash
curl -s http://localhost:9091/metrics | head
```

Example response:

```
# HELP typha_breadcrumb_block Count of the number of times Typha got the next Breadcrumb after blocking.
# TYPE typha_breadcrumb_block counter
typha_breadcrumb_block 57
# HELP typha_breadcrumb_non_block Count of the number of times Typha got the next Breadcrumb without blocking.
# TYPE typha_breadcrumb_non_block counter
typha_breadcrumb_non_block 0
# HELP typha_breadcrumb_seq_number Current (server-local) sequence number; number of snapshot deltas processed.
# TYPE typha_breadcrumb_seq_number gauge
typha_breadcrumb_seq_number 22215
...
```
{: .no-select-button}

#### CPU / memory metrics

Typha also exports the default set of metrics that Prometheus makes available.  Currently, those
include:

| Name          | Description     |
| ------------- | --------------- |
| `go_gc_duration_seconds` | A summary of the GC invocation durations. |
| `go_goroutines` | Number of goroutines that currently exist. |
| `go_memstats_alloc_bytes` | Number of bytes allocated and still in use. |
| `go_memstats_alloc_bytes_total` | Total number of bytes allocated, even if freed. |
| `go_memstats_buck_hash_sys_bytes` | Number of bytes used by the profiling bucket hash table. |
| `go_memstats_frees_total` | Total number of frees. |
| `go_memstats_gc_sys_bytes` | Number of bytes used for garbage collection system metadata. |
| `go_memstats_heap_alloc_bytes` | Number of heap bytes allocated and still in use. |
| `go_memstats_heap_idle_bytes` | Number of heap bytes waiting to be used. |
| `go_memstats_heap_inuse_bytes` | Number of heap bytes that are in use. |
| `go_memstats_heap_objects` | Number of allocated objects. |
| `go_memstats_heap_released_bytes_total` | Total number of heap bytes released to OS. |
| `go_memstats_heap_sys_bytes` | Number of heap bytes obtained from system. |
| `go_memstats_last_gc_time_seconds` | Number of seconds since 1970 of last garbage collection. |
| `go_memstats_lookups_total` | Total number of pointer lookups. |
| `go_memstats_mallocs_total` | Total number of mallocs. |
| `go_memstats_mcache_inuse_bytes` | Number of bytes in use by mcache structures. |
| `go_memstats_mcache_sys_bytes` | Number of bytes used for mcache structures obtained from system. |
| `go_memstats_mspan_inuse_bytes` | Number of bytes in use by mspan structures. |
| `go_memstats_mspan_sys_bytes` | Number of bytes used for mspan structures obtained from system. |
| `go_memstats_next_gc_bytes` | Number of heap bytes when next garbage collection will take place. |
| `go_memstats_other_sys_bytes` | Number of bytes used for other system allocations. |
| `go_memstats_stack_inuse_bytes` | Number of bytes in use by the stack allocator. |
| `go_memstats_stack_sys_bytes` | Number of bytes obtained from system for stack allocator. |
| `go_memstats_sys_bytes` | Number of bytes obtained by system. Sum of all system allocations. |
| `process_cpu_seconds_total` | Total user and system CPU time spent in seconds. |
| `process_max_fds` | Maximum number of open file descriptors. |
| `process_open_fds` | Number of open file descriptors. |
| `process_resident_memory_bytes` | Resident memory size in bytes. |
| `process_start_time_seconds` | Start time of the process since unix epoch in seconds. |
| `process_virtual_memory_bytes` | Virtual memory size in bytes. |
| `promhttp_metric_handler_requests_in_flight` | Current number of scrapes being served. |
| `promhttp_metric_handler_requests_total` | Total number of scrapes by HTTP status code. |