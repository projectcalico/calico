---
title: Logging
canonical_url: 'https://docs.projectcalico.org/v3.6/usage/troubleshooting/logging'
---

## The calico-node container

The components in the calico-node container all log to the directories under
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

See the following sub-sections for details on configuring the log level for
each calico-node component.

### Bird/Bird6

Bird and Bird6 are used for distributing IPv4 and IPv6 routes between Calico
enabled hosts.  The logs are output in the `bird` and `bird6` sub-directories
of the calico/node logging directory.

Use the `calicoctl config set loglevel` command on any host to change the
log level across all Calico nodes, _or_ use the same command with the `--node`
option to run the command for that specific node.  This command affects the
logging level for both Bird/Bird6 and Felix.

Valid log levels are:  none, debug, info, warning, error, critical.  For example:

        calicoctl config set logLevel error
        calicoctl config set logLevel debug --node=Calico-Node-1

### Felix

Felix is the primary Calico agent that runs on each machine that hosts
endpoints.  Felix is responsible for the programming of iptables rules on the
host.  The logs are output in the `felix` sub-directory of the calico/node
logging directory.

Use the `calicoctl config set loglevel` command on any host to change the
log level across all Calico nodes, _or_ use the same command with the `--node`
option to run the command for that specific node.  This command affects the
logging level for both Bird/Bird6 and Felix.

Valid log levels are:  none, debug, info, warning, error, critical.  For example:

        calicoctl config set logLevel none
        calicoctl config set logLevel error --node=Calico-Node-1

### confd

The confd agent generates configuration files for Felix and Bird using
configuration data present in the etcd datastore.  The logs are output in the
`confd` sub-directory of the calico/node logging directory.

By default, the confd logging level is "debug" and cannot be changed without
editing configuration within the node image.

For more information on the allowed levels, see the
[documentation](https://github.com/kelseyhightower/confd/blob/master/docs/configuration-guide.md)

## Docker network and IPAM driver

When running Calico as a Docker network plugin, the Calico network driver runs
inside the calico/node container.  The logs are output in the `libnetwork` sub-directory
of the calico/node logging directory.
