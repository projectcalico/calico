---
title: Felix Prometheus Statistics
---

Felix can be configured to report a number of metrics through Prometheus.  See the
[configuration reference](configuration) for how to enable metrics reporting.

## Metric Reference

#### Felix Specific

| Name          | Description     |
| ------------- | --------------- |
| `felix_resync_state`    | Current datastore state. |
| `felix_resyncs_started` | Number of datastore resyncs initiated. |


#### CPU / Memory metrics

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
