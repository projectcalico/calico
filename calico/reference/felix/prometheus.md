---
title: Prometheus statistics
description: Review metrics for the Felix component if you are using Prometheus.
canonical_url: '/reference/felix/prometheus'
---

Felix can be configured to report a number of metrics through Prometheus.  See the
[configuration reference](configuration) for how to enable metrics reporting.

## Metric reference

#### Felix specific

Felix exports a number of Prometheus metrics.  The current set is as follows.  Since some metrics
are tied to particular implementation choices inside Felix we can't make any hard guarantees that
metrics will persist across releases.  However, we aim not to make any spurious changes to
existing metrics.

| Name          | Description     |
| ------------- | --------------- |
| `felix_active_local_endpoints` | Number of active endpoints on this host. |
| `felix_active_local_policies` | Number of active policies on this host. |
| `felix_active_local_selectors` | Number of active selectors on this host. |
| `felix_calc_graph_output_events` | Number of events emitted by the calculation graph. |
| `felix_calc_graph_update_time_seconds` | Seconds to update calculation graph for each datastore OnUpdate call. |
| `felix_calc_graph_updates_processed` | Number of datastore updates processed by the calculation graph. |
| `felix_cluster_num_host_endpoints` | Total number of host endpoints cluster-wide. |
| `felix_cluster_num_hosts` | Total number of {{site.prodname}} hosts in the cluster. |
| `felix_cluster_num_workload_endpoints` | Total number of workload endpoints cluster-wide. |
| `felix_exec_time_micros` | Summary of time taken to fork/exec child processes |
| `felix_int_dataplane_addr_msg_batch_size` | Number of interface address messages processed in each batch. Higher values indicate we're doing more batching to try to keep up. |
| `felix_int_dataplane_apply_time_seconds` | Time in seconds that it took to apply a dataplane update. |
| `felix_int_dataplane_failures` | Number of times dataplane updates failed and will be retried. |
| `felix_int_dataplane_iface_msg_batch_size` | Number of interface state messages processed in each batch. Higher values indicate we're doing more batching to try to keep up. |
| `felix_int_dataplane_messages` | Number dataplane messages by type. |
| `felix_int_dataplane_msg_batch_size` | Number of messages processed in each batch. Higher values indicate we're doing more batching to try to keep up. |
| `felix_ipset_calls` | Number of ipset commands executed. |
| `felix_ipset_errors` | Number of ipset command failures. |
| `felix_ipset_lines_executed` | Number of ipset operations executed. |
| `felix_ipsets_calico` | Number of active {{site.prodname}} IP sets. |
| `felix_ipsets_total` | Total number of active IP sets. |
| `felix_iptables_chains` | Number of active iptables chains. |
| `felix_iptables_lines_executed` | Number of iptables rule updates executed. |
| `felix_iptables_restore_calls` | Number of iptables-restore calls. |
| `felix_iptables_restore_errors` | Number of iptables-restore errors. |
| `felix_iptables_rules` | Number of active iptables rules. |
| `felix_iptables_save_calls` | Number of iptables-save calls. |
| `felix_iptables_save_errors` | Number of iptables-save errors. |
| `felix_resync_state` | Current datastore state. |
| `felix_resyncs_started` | Number of times Felix has started resyncing with the datastore. |
| `felix_route_table_list_seconds` | Time taken to list all the interfaces during a resync. |
| `felix_route_table_per_iface_sync_seconds` | Time taken to sync each interface |

Prometheus metrics are self-documenting, with metrics turned on, `curl` can be used to list the
metrics along with their help text and type information.

```bash
curl -s http://localhost:9091/metrics | head
```

Example response:

```
# HELP felix_active_local_endpoints Number of active endpoints on this host.
# TYPE felix_active_local_endpoints gauge
felix_active_local_endpoints 91
# HELP felix_active_local_policies Number of active policies on this host.
# TYPE felix_active_local_policies gauge
felix_active_local_policies 0
# HELP felix_active_local_selectors Number of active selectors on this host.
# TYPE felix_active_local_selectors gauge
felix_active_local_selectors 82
...
```
{: .no-select-button}

#### CPU / memory metrics

Felix also exports the default set of metrics that Prometheus makes available.  Currently, those
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


#### Wireguard Metrics

Felix also exports wireguard device stats if found/detected. Can be disabled via Felix configuration.


| Name          | Description     |
| ------------- | --------------- |
| `wireguard_meta` | Gauge. Device / interface information for a felix/calico node, values are in this metric's labels |
| `wireguard_bytes_rcvd` | Counter. Current bytes received from a peer identified by a peer public key and endpoint |
| `wireguard_bytes_sent` | Counter. Current bytes sent to a peer identified by a peer public key and endpoint |
| `wireguard_latest_handshake_seconds` | Gauge. Last handshake with a peer, unix timestamp in seconds. |
