---
title: calicoctl config
canonical_url: 'https://docs.projectcalico.org/v1.6/reference/calicoctl/config'
---

This sections describes the `calicoctl config` commands.

The `calicoctl config` command allows users to view or modify
low-level component configurations for Felix and BGP.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl config' commands

Run `calicoctl config --help` to display the following help menu for the
calicoctl config commands.

```shell
Usage:
  calicoctl config felix <NAME> [<VALUE>|--remove] [--force]
  calicoctl config bgp <NAME> [<VALUE>|--remove] [--force]
  calicoctl config node bgp <NAME> [<VALUE>|--remove] [--force]

Description:
  Configure or show low-level component configuration for Felix and BGP.

Options:
 --remove  Remove the configuration entry.
 --force   Force update of configuration entry even if key value is unknown,
           or the value is not recognized as valid.

Valid configuration:
  Command         | <NAME>   | <VALUE>s
------------------+----------+-----------------------------------------
  config felix    | loglevel | none debug info warning error critical
  config bgp      | loglevel | none debug info
  config node bgp | loglevel | none debug info

Warnings:
  -  Changing the global BGP logging levels using the `calicoctl config bgp`
     command may cause all BGP sessions to bounce potentially resulting in a
     transient loss of service.  If you need to change the logging level for
     BGP, it is recommended to change the levels on a per-node basis using
     the `calicoctl config node bgp` command.

```

## calicoctl config commands


### calicoctl config felix \<NAME\>
This command allows you to show or modify key values for configuration
associated with the Felix process.

Currently, you can modify the following:

```shell
  Command         | <NAME>   | <VALUE>s
------------------+----------+-----------------------------------------
  config felix    | loglevel | none debug info warning error critical
```

`loglevel` represents the logging level of messages sent to the Felix log file.
All messages with a lower priority than the `loglevel` value will be filtered
out. All Calico logs can be found `/var/log/calico`, unless a different log
directory was specified in the [`calicoctl node`](node) command.


This command can be run on any Calico node and affects every Felix in the
cluster.

Command syntax:

```
calicoctl config felix <NAME> [<VALUE>|--remove] [--force]

    <NAME>: Config variable key in question.
    <VALUE>: Value to assign to the config variable.

    --remove: Remove the config key value.
    --force: Force update of config, even if key or value are unknown.
```
The `--remove` flag allows you to completely remove the value from the etcd
datastore.  Felix will instead read a value from the Felix config file.

The `--force` flag is used to configure a value on the config key that the
`calicoctl config` command does not recognize.  A warning message appears if an
unrecognized value is passed into the command.  This flag allows you to
override the warning message use a value that is not in the recognized list.

Examples:

```
$ calicoctl config felix loglevel
info

$ calicoctl config felix loglevel debug

$ calicoctl config felix loglevel --remove
Value removed
```

### calicoctl config bgp \<NAME\>
This command allows you to show or modify key values for configuration
associated with the BGP process.

Currently, you can modify the following:

```shell
  Command         | <NAME>   | <VALUE>s
------------------+----------+----------------
  config bgp      | loglevel | none debug info
```

`loglevel` represents the logging level of messages sent to the BIRD BGP daemon
log file. All messages with a lower priority than the `loglevel` value will be
filtered out. All Calico logs can be found `/var/log/calico`, unless a different log
directory was specified in the [`calicoctl node`](./node) command.

This command can be run on any Calico node and affects all of the BIRD processes
in the cluster.

Command syntax:

```
calicoctl config bgp <NAME> [<VALUE>|--remove] [--force]

    <NAME>: Config variable key in question.
    <VALUE>: Value to assign to the config variable.

    --remove: Remove the config key value.
    --force: Force update of config, even if key or value are unknown.
```
The `--remove` flag allows you to completely remove the value from the etcd
datastore.  The process reading the value then determines a value to use
internally.

The `--force` flag is used to configure a value on the config key that the
`calicoctl config` command does not recognize.  A warning message appears if an
unrecognized value is passed into the command.  This flag allows you to
override the warning message use a value that is not in the recognized list.

Examples:

```
$ calicoctl config bgp loglevel
info

$ calicoctl config bgp loglevel debug


$ calicoctl config bgp loglevel --remove
Value removed
```

### calicoctl config node bgp \<NAME\>
This command allows you to show or modify key values for configuration
associated with the BGP process on individual nodes.

Currently, you can modify the following:
```
  Command         | <NAME>   | <VALUE>s
------------------+----------+----------------
  config node bgp | loglevel | none debug info
```

`loglevel` represents the logging level of messages sent to the BIRD BGP daemon
log file. All messages with a lower priority than the `loglevel` value will be
filtered out. All Calico logs can be found `/var/log/calico`, unless a different log
directory was specified in the [`calicoctl node`](./node) command.

This command must be run on the specific Calico node that you want to configure.

Command syntax:

```
calicoctl config node bgp <NAME> [<VALUE>|--remove] [--force]

    <NAME>: Config variable key in question.
    <VALUE>: Value to assign to the config variable.

    --remove: Remove the config key value.
    --force: Force update of config, even if key or value are unknown.
```
The `--remove` flag allows you to completely remove the value from the etcd
datastore.  The process reading the value then determines a value to use
internally.

The `--force` flag is used to configure a value on the config key that the
`calicoctl config` command does not recognize.  A warning message appears if an
unrecognized value is passed into the command.  This flag allows you to
override the warning message to use a value that is not in the recognized list.

Examples:

```
$ calicoctl config node bgp loglevel
info

$ calicoctl config node bgp loglevel debug

$ calicoctl config node bgp loglevel --remove
Value removed
```
