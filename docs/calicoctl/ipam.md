<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# User reference for 'calicoctl ipam' commands

This section describes the `calicoctl ipam` commands.

This command allows an interface into Calico's IP address management to release 
IP addresses from endpoints and view additional information about assigned IPs.

Read the [calicoctl command line interface user reference](../calicoctl.md) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam' commands

Run `calicoctl ipam --help` to display the following help menu for the 
calicoctl ipam commands.

```

Usage:
  calicoctl ipam release <IP>
  calicoctl ipam info <IP>

Description:
  Manage Calico assigned IP addresses

Warnings:
  -  Releasing an in-use IP address can result in it being assigned to multiple
     workloads.

```

## calicoctl ipam commands


### calicoctl ipam release <IP>

This command allows you to release an IP address that had been previously 
assigned to an endpoint.  When an IP address is released, it becomes available 
for assignment to any endpoint.

Note that this does not remove the IP from any existing endpoints that may be 
using it, so we generally recommend you use this command to clean up addresses 
from endpoints that were not cleanly removed from Calico.

This command can be run on any Calico node. 

Command syntax:

```
calicoctl ipam release <IP>

    <IP>: IP address to release.
```

Examples:

```
$ calicoctl ipam release 192.168.1.1
Address successfully released

$ calicoctl ipam release fd80:24e2:f998:72d6::1
Address successfully released
```

### calicoctl ipam info <IP>

This command prints information about a given IP address, such as special 
attributes defined for the IP or whether the IP has been reserved by a user of 
the Calico IPAM.

This command can be run on any Calico node.

Command syntax:

```
calicoctl ipam info <IP>

    <IP>: IP address desired to view information about.
```

Examples:

```
# IP is not assigned to an endpoint
$ calicoctl ipam info 192.168.1.2
IP 192.168.1.2 is not currently assigned

# Basic Docker container has the assigned IP
$ calicoctl ipam info 192.168.1.1
No attributes defined for 192.168.1.1
```
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calicoctl/ipam.md?pixel)](https://github.com/igrigorik/ga-beacon)
