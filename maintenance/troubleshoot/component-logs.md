---
title: Component logs
description: Where to find component logs.
canonical_url: '/maintenance/troubleshoot/component-logs'
---

## The {{site.nodecontainer}} container

The components in the `{{site.nodecontainer}}` container all log to the directories under
`/var/log/calico` inside the container.  By default this is mapped to the
`/var/log/calico` directory on the host but can be changed by specifying a
`--log-dir` parameter on the `calicoctl node run` command.

Each component (described below) logs to its own directory. Files are
automatically rotated, and by default 10 files of 1MB each are kept. The
current log file is called `current` and rotated files have @ followed by a
timestamp detailing when the files was rotated in [tai64n](http://cr.yp.to/libtai/tai64.html#tai64n){:target="_blank"} format.

All logging is done using [svlogd](http://smarden.org/runit/svlogd.8.html){:target="_blank"}.
Each component can be configured by dropping a file named `config` into that
component's logging directory.

svlogd can be configured to forward logs to syslog, to prefix each line
and to filter logs.
See the [documentation](http://smarden.org/runit/svlogd.8.html){:target="_blank"} for further details.

e.g. to configure bird to only log 4 files of 10KB each, create a file called `config` in the `/var/log/calico/bird` directory containing
```
#/var/log/calico/bird/config
s10000
n4
```

e.g. to configure bird to drop logs with the suffix `Netlink: File exists`, create a file called `config` in the `/var/log/calico/bird` directory containing
```
-*Netlink: File exists
```

See the following subsections for details on configuring the log level for
each `{{site.nodecontainer}}` component.

### Bird/Bird6

Bird and Bird6 are used for distributing IPv4 and IPv6 routes between {{site.prodname}}
enabled hosts.  The logs are output in the `bird` and `bird6` sub-directories
of the `{{site.nodecontainer}}` logging directory.

* The Debug level enables "debug all" logging for bird.
* The Info level (default) only enabled "debug {states}" logging. This is for protocol state changes (protocol going up, down, starting, stopping etc.)
* The Warning, Error and Fatal levels all turn off bird debug logging completely.

See [BGP Configuration Resource](/reference/resources/bgpconfig)
for details on how to modify the logging level. For example:


1. Get the current bgpconfig settings.

   ```bash
   calicoctl get bgpconfig -o yaml > bgp.yaml
   ```

1. Modify logSeverityScreen to desired value.

   ```bash
   vim bgp.yaml
   ```

   > **Tip**: For a global change set the name to "default".
   > For a node-specific change set the name to the node name prefixed with "node.", e.g., "node.node-1".
   {: .alert .alert-success}

1. Replace the current bgpconfig settings.

   ```bash
   calicoctl replace -f bgp.yaml
   ```

### Felix

Felix is the primary {{site.prodname}} agent that runs on each machine that hosts
endpoints.  Felix is responsible for the programming of iptables rules on the
host.  The logs are output in the `felix` sub-directory of the `{{site.nodecontainer}}`
logging directory.

1. Get the current felixconfig settings.

   ```bash
   calicoctl get felixconfig -o yaml > felix.yaml
   ```

1. Modify logSeverityScreen to desired value.

   ```bash
   vim felix.yaml
   ```

   > **Tip**: For a global change set the name to "default".
   > For a node-specific change set the name to the node name, e.g., "{{site.prodname}}-Node-1".
   {: .alert .alert-success}

1. Replace the current felixconfig settings.

   ```bash
   calicoctl replace -f felix.yaml
   ```

### confd

The confd agent generates configuration files for Felix and Bird using
configuration data present in the etcd datastore.  The logs are output in the
`confd` sub-directory of the `{{site.nodecontainer}}` logging directory.

By default, the confd logging level is "debug" and cannot be changed without
editing configuration within the node image.

For more information on the allowed levels, see the
[documentation](https://github.com/kelseyhightower/confd/blob/master/docs/configuration-guide.md){:target="_blank"}
