---
title: calicoctl CLI user reference
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/calicoctl/'
---

The command line tool, `calicoctl`, makes it easy to configure and start Calico
services and to manage Calico network and security policy.

The tool provides a simple interface for using Calico networking with Docker
containers.  In addition, many of the calicoctl commands are useful for general
management of Calico configuration regardless of whether you are running Calico
on VMs, containers or bare metal.

This user reference is organized in sections based on the top level command options
of calicoctl.

## Top level help

Run `calicoctl --help` to display the following help menu for the top level 
calicoctl commands.

```
calicoctl

Override the host:port of the ETCD server by setting the environment variable
ETCD_AUTHORITY [default: 127.0.0.1:2379]

Usage: calicoctl <command> [<args>...]

    status            Print current status information
    node              Configure the main calico/node container and establish Calico networking
    container         Configure containers and their addresses
    profile           Configure endpoint profiles
    endpoint          Configure the endpoints assigned to existing containers
    pool              Configure ip-pools
    bgp               Configure global bgp
    ipam              Configure IP address management
    checksystem       Check for incompatibilities on the host system
    diags             Save diagnostic information
    version           Display the version of calicoctl
    config            Configure low-level component configuration

See 'calicoctl <command> --help' to read about a specific subcommand.

```


## Top level command line options

Details on the `calicoctl` commands are described in the documents linked below
organized by top level command.

-  [calicoctl status](status)
-  [calicoctl node](node)
-  [calicoctl container](container)
-  [calicoctl profile](profile)
-  [calicoctl endpoint](endpoint)
-  [calicoctl pool](pool)
-  [calicoctl bgp](bgp)
-  [calicoctl ipam](ipam)
-  [calicoctl checksystem](checksystem)
-  [calicoctl diags](diags)
-  [calicoctl version](version)
-  [calicoctl config](config)

