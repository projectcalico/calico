---
title: Logging
canonical_url: 'https://docs.projectcalico.org/v3.3/usage/troubleshooting/logging'
---

## The calico-node container

The components in the calico-node container all log to the directories under
`/var/log/calico` inside the container.  By default this is mapped to the
`/var/log/calico` directory on the host but can be changed by specifying a
`--log-dir` parameter on the `calicoctl node` command.

By default, each component (below) logs to its own directory. Files are
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
enabled hosts.

Directory | Default level
--- | ---
`bird` and `bird6` | `info`

Use the `calicoctl config bgp loglevel` command on any host to change the
log level across all BGP nodes, _or_ use the `calicoctl config node bgp loglevel`
command on a specific host to change the log level for that specific BGP node.

Valid log levels are:  none, debug and info.  e.g.

        calicoctl config bgp loglevel none
        calicoctl config node bgp loglevel debug

### Felix
Felix is the primary Calico agent that runs on each machine that hosts
endpoints.  Felix is responsible for the programming of iptables rules on the
host.

Directory | Default level
--- | ---
`felix` | `info`

Use the `calicoctl config felix loglevel` command on any host to change the
log level on all Felix instances.

Valid log levels are:  none, debug, info, warning, error, critical

        calicoctl config felix loglevel error

### confd
The confd agent generates configuration files for Felix and Bird using
configuration data present in the etcd datastore.

Directory | Default level
--- | ---
`confd` | `DEBUG`

To change the log level, edit the node_filesystem/etc/service/confd/run and
rebuild the calico-node image.

For more information on the allowed levels, see the
[documentation](https://github.com/kelseyhightower/confd/blob/master/docs/configuration-guide.md)


## Docker network and IPAM driver
When running Calico as a Docker network plugin (i.e. using the `--libnetwork`
option on the `calicoctl node` command), the Calico driver is run in a separate
calico-libnetwork container.

The logs may be viewed running the standard `docker logs` command for this
container.  e.g.

    docker logs calico-libnetwork

For details on how to change the log levels for the plugin, please view the
[libnetwork-plugin documentation](https://github.com/projectcalico/libnetwork-plugin/blob/master/README.md).
