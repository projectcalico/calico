---
title: calicoctl pool
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/calicoctl/resources/ippool'
---

> NOTE: ONLY the `calicoctl pool show` command is safe to use when running
> Calico with the Docker libnetwork driver. The libnetwork driver manages the
> IP address pools and assignment.  

This sections describes the `calicoctl pool` commands.

These commands allow users to define and view IP address pools from which endpoint
IP addresses are allocated.  Users can add, remove, update, or view the IP pools.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for a
full list of calicoctl commands.

## Displaying the help text for 'calicoctl pool' commands

Run `calicoctl pool --help` to display the following help menu for the
calicoctl pool commands.

```

Usage:
  calicoctl pool add <CIDRS>... [--ipip] [--nat-outgoing]
  calicoctl pool remove <CIDRS>...
  calicoctl pool range add <START_IP> <END_IP> [--ipip] [--nat-outgoing]
  calicoctl pool show [--ipv4 | --ipv6]

Description:
  Configure IP Pools

Options:
  --ipv4          Show IPv4 information only
  --ipv6          Show IPv6 information only
  --nat-outgoing  Apply NAT to outgoing traffic
  --ipip          Use IP-over-IP encapsulation across hosts

```

## calicoctl pool commands


### calicoctl pool add
This command is used to add or modify CIDR pools in Calico.

Pools define the range of IP addresses that Calico considers endpoint IPs to
be from. In order to function correctly, all endpoint IPs must fall within a
configured pool. This happens automatically for the libnetwork plug-in or any
system that uses Calico IPAM to assign IPs to endpoints.

The command can be run on any machine that can access the etcd datastore, such
as a Calico node host.

Command syntax:

```
calicoctl pool add <CIDRS>... [--ipip] [--nat-outgoing]

    <CIDRS>: A single or list of cidrs separated by spaces.

    --ipip: Use IP-over-IP encapsulation across hosts.
    --nat-outgoing: Apply a NAT to outgoing traffic.
```

Any time that Calico IPAM is in use, including with Docker default networking,
Mesos, and Kubernetes (when Calico IPAM is enabled), Calico will allocate IP
addresses from pools and assign them to newly created containers. The allocated
IP addresses provide network endpoints to the containers.

Examples:

```
# Add a pool to Calico
$ calicoctl pool add 192.168.0.0/16

# Add two pools to Calico with IP-over-IP encapsulation and NAT
$ calicoctl pool add 192.168.0.0/16 172.24.10.0/24 --ipip --nat-outgoing
```

### calicoctl pool remove
This command is used to remove configured CIDR pools from Calico.

The command can be run on any Calico node.

Command syntax:

```
calicoctl pool remove <CIDRS>...

    <CIDRS>: A single or list of CIDRs separated by spaces.
```

Examples:

```
$ calicoctl pool remove 172.24.10.0/24
```

### calicoctl pool range add \<START_IP\> \<END_IP\>
This command adds all IP addresses between two IPs as Calico pool(s).

NOTE: Calico pools must be identified with a CIDR prefix, so in the case that
the start and end of the range are not on a single CIDR boundary, this command
creates multiple pools such that the entire range is covered.

This command can be run on any Calico node.

Command syntax:

```
calicoctl pool range add <START_IP> <END_IP> [--ipip] [--nat-outgoing]

    <START_IP>: IP to include from beginning of pool range.
    <END_IP>: IP to include as the final IP in the pool range.

    --ipip: Use IP-over-IP encapsulation across hosts.
    --nat-outgoing: Apply a NAT to outgoing traffic.
```

IP pools are added to Calico based on the IPs within the range specified.

Examples:

```
# Add pools for all IPs between 172.24.0.0 172.24.25.255
$ calicoctl pool range add 172.24.0.0 172.24.25.255

# Show the newly created pools
$ calicoctl pool show
+----------------+---------+
|   IPv4 CIDR    | Options |
+----------------+---------+
| 172.24.0.0/20  |         |
| 172.24.16.0/21 |         |
| 172.24.24.0/23 |         |
+----------------+---------+
```

### calicoctl pool show
This command prints the currently available Calico IP pools and their options.

This command can be run on any Calico node.

Command syntax:

```
calicoctl pool show [--ipv4 | --ipv6]

    --ipv4: Show IPv4 pools only.
    --ipv6: Show IPv6 pools only.
```

Examples:

```
$ calicoctl pool show
+----------------+-------------------+
|   IPv4 CIDR    |      Options      |
+----------------+-------------------+
| 172.25.0.0/16  | ipip,nat-outgoing |
| 192.168.0.0/16 |                   |
+----------------+-------------------+
+--------------------------+---------+
|        IPv6 CIDR         | Options |
+--------------------------+---------+
| fd80:24e2:f998:72d6::/64 |         |
+--------------------------+---------+
```
