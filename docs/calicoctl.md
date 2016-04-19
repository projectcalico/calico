<!--- master only -->
> ![warning](images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# calicoctl command line interface user reference

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

-  [calicoctl status](calicoctl/status.md)
-  [calicoctl node](calicoctl/node.md)
-  [calicoctl container](calicoctl/container.md)
-  [calicoctl profile](calicoctl/profile.md)
-  [calicoctl endpoint](calicoctl/endpoint.md)
-  [calicoctl pool](calicoctl/pool.md)
-  [calicoctl bgp](calicoctl/bgp.md)
-  [calicoctl ipam](calicoctl/ipam.md)
-  [calicoctl checksystem](calicoctl/checksystem.md)
-  [calicoctl diags](calicoctl/diags.md)
-  [calicoctl version](calicoctl/version.md)
-  [calicoctl config](calicoctl/config.md)

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calicoctl.md?pixel)](https://github.com/igrigorik/ga-beacon)
