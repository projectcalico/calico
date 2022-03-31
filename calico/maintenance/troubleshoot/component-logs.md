---
title: Component logs
description: Where to find component logs.
canonical_url: '/maintenance/troubleshoot/component-logs'
---

### Big picture

View and collect {{site.prodname}} logs.

### Value

It is useful to view logs to monitor component health and diagnose potential issues.

### Concepts

#### {{site.nodecontainer}} logs

The {{site.nodecontainer}} logs contain log output from the following subcomponents:

- Per-node startup logic
- BGP agent
- Felix policy agent

Components log either to disk within `/var/log/calico`, to stdout, or both.

For components that log to disk, files are automatically rotated, and by default 10 files of 1MB each are kept. The current log file is called `current` and rotated files have @ followed by a timestamp detailing when the files was rotated in [tai64n](http://cr.yp.to/libtai/tai64.html#tai64n){:target="_blank"} format.

### How to

### View logs for a {{site.nodecontainer}} instance

You can view logs for a node using the `kubectl logs` command. This will show logs for all subcomponents of the given node.

For example:

```
kubectl logs -n calico-system calico-node-xxxx
```

### View logs from the CNI plugin

CNI plugin logs are not available through kubectl and are instead logged both to the host machine's disk as well as stderr.

By default, these logs can be found at `/var/log/calico/cni/` on the host machine.

The container runtime may also display the CNI plugin logs within its own log output.

### Configure BGP agent log level

BGP log level is configured via the [BGPConfiguration]({{site.baseurl}}/reference/resources/bgpconfig) API, and can be one of the following values:

- `Debug`: enables "debug all" logging for BIRD. The most verbose logging level.
- `Info`: enables logging for protocol state changes. This is the default log level.
- `Warning`: disables BIRD logging, emits warning level configuration logs only.
- `Error`: disables BIRD logging, emits error level configuration logs only.
- `Fatal`: disables BIRD logging, emits fatal level configuration logs only.

To modify the BGP log level:

1. Get the current bgpconfig settings.

   ```bash
   kubectl get bgpconfig -o yaml > bgp.yaml
   ```

1. Modify logSeverityScreen to the desired value.

   ```bash
   vim bgp.yaml
   ```

   > **Tip**: For a global change set the name to "default".
   > For a node-specific change set the name to the node name prefixed with "node.", e.g., "node.node-1".
   {: .alert .alert-success}

1. Replace the current bgpconfig settings.

   ```bash
   kubectl replace -f bgp.yaml
   ```

### Configure Felix log level

Felix log level is configured via the [FelixConfiguration]({{site.baseurl}}/reference/resources/felixconfig) API, and can be one of the following values:

- `Debug`: The most verbose logging level - for development and debugging.
- `Info`: The default log level. Shows important state changes.
- `Warning`: Shows warnings only.
- `Error`: Shows errors only.
- `Fatal`: Shows fatal errors only.

To modify Felix's log level:

1. Get the current felixconfig settings.

   ```bash
   kubectl get felixconfig -o yaml > felixconfig.yaml
   ```

1. Modify logSeverityScreen to desired value.

   ```bash
   vim felixconfig.yaml
   ```

   > **Tip**: For a global change set the name to "default".
   > For a node-specific change set the name to the node name, e.g., "{{site.prodname}}-Node-1".
   {: .alert .alert-success}

1. Replace the current felixconfig settings.

   ```bash
   kubectl replace -f felixconfig.yaml
   ```
