---
title: Logging
redirect_from: latest/usage/troubleshooting/logging
canonical_url: 'https://docs.projectcalico.org/v3.1/usage/troubleshooting/logging'
---

## The {{site.nodecontainer}} container

The components in the `{{site.nodecontainer}}` container all log to the directories under
`/var/log/calico` inside the container.  By default this is mapped to the
`/var/log/calico` directory on the host but can be changed by specifying a
`--log-dir` parameter on the `calicoctl node run` command.

Each component (described below) logs to its own directory. Files are
automatically rotated, and by default 10 files of 1MB each are kept. The
current log file is called `current` and rotated files have @ followed by a
timestamp detailing when the files was rotated in [tai64n](http://cr.yp.to/libtai/tai64.html#tai64n) format.

All logging is done using [svlogd](http://smarden.org/runit/svlogd.8.html).
Each component can be configured by dropping a file named `config` into that
component's logging directory.

e.g. to configure bird to only log 4 files of 10KB each

```shell
#/var/log/calico/bird/config
s10000
n4
```

svlogd can also be configured to forward logs to syslog, to prefix each line
and to filter logs. See the [documentation](http://smarden.org/runit/svlogd.8.html)
for further details.

See the following subsections for details on configuring the log level for
each `{{site.nodecontainer}}` component.

### Bird/Bird6

Bird and Bird6 are used for distributing IPv4 and IPv6 routes between {{site.prodname}}
enabled hosts.  The logs are output in the `bird` and `bird6` sub-directories
of the `{{site.nodecontainer}}` logging directory.

See [BGP Configuration Resource](/{{page.version}}/reference/calicoctl/resources/bgpconfig) 
for details on how to modify the logging level. For example:

```
# Get the current bgpconfig settings
$ calicoctl get bgpconfig -o yaml > bgp.yaml

# Modify logSeverityScreen to none, debug, info, etc.
#   Global change: set name to "default"
#   Node-specific change: set name to the node name, e.g. "{{site.prodname}}-Node-1"
$ vim bgp.yaml

# Replace the current bgpconfig settings
$ calicoctl replace -f bgp.yaml
```

### Felix

Felix is the primary {{site.prodname}} agent that runs on each machine that hosts
endpoints.  Felix is responsible for the programming of iptables rules on the
host.  The logs are output in the `felix` sub-directory of the `{{site.nodecontainer}}`
logging directory.

```
# Get the current felixconfig settings
$ calicoctl get felixconfig -o yaml > felix.yaml

# Modify logSeverityScreen to none, debug, info, etc.
#   Global change: set name to "default"
#   Node-specific change: set name to the node name, e.g. "{{site.prodname}}-Node-1"
$ vim felix.yaml

# Replace the current felixconfig settings
$ calicoctl replace -f felix.yaml
```

### confd

The confd agent generates configuration files for Felix and Bird using
configuration data present in the etcd datastore.  The logs are output in the
`confd` sub-directory of the `{{site.nodecontainer}}` logging directory.

By default, the confd logging level is "debug" and cannot be changed without
editing configuration within the node image.

For more information on the allowed levels, see the
[documentation](https://github.com/kelseyhightower/confd/blob/master/docs/configuration-guide.md)

## Docker network and IPAM driver

When running {{site.prodname}} as a Docker network plugin, the {{site.prodname}} network driver runs
inside the `{{site.nodecontainer}}` container.  The logs are output in the `libnetwork` sub-directory
of the `{{site.nodecontainer}}` logging directory.
