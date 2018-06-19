---
title: calicoctl container
sitemap: false 
---

> NOTE: The `calicoctl container` configuration commands are used specifically
> when running Calico with Docker default (bridge) networking.  These commands
> should  NOT be used when running Calico with Kubernetes, Mesos, the Docker
> libnetwork driver, or other orchestrators.

This sections describes the `calicoctl container` commands.

These commands can be used to manage Calico networking for Docker containers.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for a
full list of calicoctl commands.

## Displaying the help text for 'calicoctl container' commands

Run `calicoctl container --help` to display the following help menu for the
calicoctl container commands.

```

Usage:
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER>
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container <CONTAINER> endpoint show
  calicoctl container <CONTAINER> profile (append|remove|set) [<PROFILES>...]

Description:
  Add or remove containers to calico networking, manage their IP addresses and profiles.
  All these commands must be run on the host that contains the container.

Options:
  --interface=<INTERFACE>  The name to give to the interface in the container
                           [default: eth1]

```

## calicoctl container commands


### calicoctl container add \<CONTAINER\> \<IP\>

This command allows you to add a container into the Calico network.

This command is required for any container created using default Docker
networking to use Calico.  This command creates a new network interface within
the container, connects it to the Calico network, and assigns the given IP
address.

To configure networking policy on a container after it has been added to
Calico, create a profile using `calicoctl profile add` (see the
[`calicoctl profile` guide](./profile)) and set the profile on the container
using the `calicoctl container <CONTAINER> profile add <PROFILE>` command (see
below).

This command must be run as root and must be run on the specific Calico node
that hosts the container.

Command syntax:

```
calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]

    <CONTAINER>: The name or ID of the container.
    <IP>: An IP address, IP version, or pool expressed as a CIDR prefix.
    <INTERFACE>: The name to give to the interface in the container.
                 [default: eth1]
```

The `<IP>` parameter can be expressed in three different ways:
 - IP address: an IPv4 or IPv6 address from within a Calico pool
 - IP version: "ipv4" or "ipv6", which will automatically select an IP address
               from an existing Calico pool with the given IP version.
 - IP CIDR: an IP address CIDR representing an existing Calico pool, which will
            automatically select an IP from the pool.

NOTE: Since Calico is fully routed, you do not have to worry about conflicts
with addresses that are commonly reserved L2 subnets, such as the subnet
network and broadcast addresses. It is perfectly okay to assign an IP address
that ends in .0 or .255 to a workload.

If you specify the `--interface` flag, Calico will use the passed in value as
the name of the new Calico interface.

Examples:

```
$ calicoctl container add test-container 192.168.1.1
IP 192.168.1.1 added to test-container

$ calicoctl container add test-container ipv6 --interface=eth1
IP fd80:24e2:f998:72d6::1 added to test-container

$ calicoctl container add test-container 192.168.0.0/16
IP 192.168.0.1 added to test-container

$ calicoctl container add test-container ipv4
IP 192.168.0.0 added to test-container
```

### calicoctl container remove \<CONTAINER\>

This command allows you to remove a container from the Calico network.

This command must be run as root and must be run on the specific Calico node
that hosts the container.

Command syntax:

```
calicoctl container remove <CONTAINER>

    <CONTAINER>: The name or ID of the container
```

Examples:

```
$ calicoctl container remove test-container
Removed Calico interface from test-container
```

### calicoctl container \<CONTAINER\> ip add \<IP\>

This command allows you to add an IP address to a container that has already
been configured to use Calico networking with the `calicoctl container add`
command (see above).

This command must be run as root on the specific Calico node that hosts the
container.

Command syntax:

```
calicoctl container <CONTAINER> ip add <IP> [--interface=<INTERFACE>]

Parameters:
    <CONTAINER>: The name or ID of the container
    <IP>: The IPv4 or IPv6 address to add.
    --interface=<INTERFACE>  The name to give to the interface in the container
                             [default: eth1]

```
The `<IP>` parameter can be expressed in three different ways:
 - IP address: an IPv4 or IPv6 address from within a Calico pool
 - IP version: "ipv4" or "ipv6", which will automatically select an IP address
               from an existing Calico pool with the given IP version.
 - IP CIDR: an IP address CIDR representing an existing Calico pool, which will
            automatically select an IP from the pool.

NOTE: If you specify the `--interface` flag, the interface passed in must
already exist within the container.

Examples:

```
$ calicoctl container test-container ip add 192.168.2.2
IP 192.168.2.2 added to test-container

$ calicoctl container add test-container ipv6 --interface=eth1
IP fd80:24e2:f998:72d6::6 added to test-container

calicoctl container add test-container 192.168.0.0/16
IP 192.168.4.24 added to test-container
```

### calicoctl container \<CONTAINER\> ip remove \<IP\>

This command allows you to remove an IP address from a container that is
using Calico networking.

This command must be run as root and must be run on the specific Calico node
that hosts the container.

Command syntax:

```
calicoctl container <CONTAINER> ip remove <IP> [--interface=<INTERFACE>]

    <INTERFACE>: The name to give to the interface in the container
                 [default: eth1]
    <CONTAINER>: The name or ID of the container
    <IP>: The IPv4 or IPv6 address to add.
```

Examples:

```
$ calicoctl container test-container ip remove 192.10.0.3 --interface=eth1
IP 192.10.0.3 removed from test-container
```

### calicoctl container \<CONTAINER\> endpoint show

This command allows you to view information about the endpoint associated with
a container.  The endpoint ID is used by the
[`calicoctl endpoint`](endpoint) commands for manipulating and viewing
endpoint configuration.

This command must be run on the specific Calico node that hosts the container.

Command syntax:

```
calicoctl container <CONTAINER> endpoint show

    <CONTAINER>: The name or ID of the container
```

Examples:

```
$ calicoctl container test-container endpoint show
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+
| Hostname | Orchestrator ID |                           Workload ID                            |           Endpoint ID            |   Addresses    |        MAC        | Profiles | State  |
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+
|  calico  |      docker     | 0d01b3f020fcadfd0090fcbbbbef9658acb26f71c1cb812827afafc625c5ae1a | d79123c4784511e5bd1a080027f532f6 | 192.168.1.4/32 | d6:43:59:f7:93:d3 |          | active |
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+
```
