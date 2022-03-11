---
title: Prometheus statistics
description: Review metrics for the kube-controllers component if you are using Prometheus.
canonical_url: '/reference/kube-controllers/prometheus'
---

kube-controllers can be configured to report a number of metrics through Prometheus.  This reporting is enabled by default on port 9094. See the
[configuration reference]({{site.baseurl}}/reference/resources/kubecontrollersconfig) for how to change metrics reporting configuration (or disable it completely).

## Metric reference

#### kube-controllers specific

kube-controllers exports a number of Prometheus metrics.  The current set is as follows.  Since some metrics
may be tied to particular implementation choices inside kube-controllers we can't make any hard guarantees that
metrics will persist across releases.  However, we aim not to make any spurious changes to
existing metrics.

| Metric Name  | Labels  | Description |
|--------------|---------|-------------|
| `ipam_allocations_in_use` | ippool, node | Number of Calico IP allocations currently in use by a workload or interface. |
| `ipam_allocations_borrowed` | ippool, node | Number of Calico IP allocations currently in use where the allocation was borrowed from a block affine to another node. |
| `ipam_allocations_gc_candidates` | ippool, node | Number of Calico IP allocations currently marked by the GC as potential leaks. This metric returns to zero under normal GC operation. |
| `ipam_allocations_gc_reclamations` | ippool, node | Count of Calico IP allocations that have been reclaimed by the GC. Increase of this counter corresponds with a decrease of the candidates gauge under normal operation. |
| `ipam_blocks` | ippool, node | Number of IPAM blocks. |
| `ipam_ippool_size` | ippool  | Number of IP addresses in the IP Pool CIDR. |
| `ipam_blocks_per_node` | node    | Number of IPAM blocks, indexed by the node to which they have affinity. Prefer `ipam_blocks` for new integrations. |
| `ipam_allocations_per_node` | node    | Number of Calico IP allocations, indexed by node on which the allocation was made. Prefer `ipam_allocations_in_use` for new integrations. |
| `ipam_allocations_borrowed_per_node` | node    | Number of Calico IP allocations borrowed from a non-affine block, indexed by node on which the allocation was made. Prefer `ipam_allocations_borrowed` for new integrations. |

Labels can be interpreted as follows:

| Label Name | Description |
|------------|-------------|
| `node`     | For allocation metrics, the node on which the allocation was made. For block metrics, the node for which the block has affinity. If the block has no affinity, value will be `no_affinity`. |
| `ippool`   | The IP Pool that the IPAM block occupies. If there is no IP Pool which matches the block, value will be `no_ippool`. |

Prometheus metrics are self-documenting, with metrics turned on, `curl` can be used to list the
metrics along with their help text and type information.

```bash
curl -s http://localhost:9094/metrics | head
```
#### CPU / memory metrics

kube-controllers also exports the default set of metrics that Prometheus makes available.  Currently, those
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
