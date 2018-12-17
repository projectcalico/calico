---
title: calicoctl status
canonical_url: 'https://docs.projectcalico.org/v3.4/reference/calicoctl/commands/node/status'
---

This sections describes the `calicoctl status` commands.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl status' commands

Run `calicoctl status --help` to display the following help menu for the
calicoctl status commands.

```

Usage:
  calicoctl status

Description:
  Print current status information regarding calico-node container
  and the BIRD routing daemon.

```

## calicoctl status commands


### calicoctl status
This command allows you to view state information about the `calico/node` and
the BGP peers of the Calico node.

This command shows:

 - State and uptime of `calico/node` container
 - BGP State for IPv4 and IPv6 peers
   - Peer address: Host address used as BGP peer IP to route to Calico workloads
   - Peer type: How the two BGP peers are connected, such as through a
   `node-to-node mesh`, a direct peer between two nodes as `node-specific`,
   or as a `global` BGP peer (See the [`calicoctl bgp` reference](bgp) for
   more info)
   - State: Peer instance state, `up` or `down`
   - Since: How long the peer has been up
   - Info: BGP connection state, such as Established


Command syntax:

```
calicoctl status
```

Examples:

```
$ calicoctl status
calico-node container is running. Status: Up 5 seconds

IPv4 BGP status
IP: 172.17.8.100    AS Number: 64511 (inherited)
+--------------+-------------------+-------+----------+-------------+
| Peer address |     Peer type     | State |  Since   |     Info    |
+--------------+-------------------+-------+----------+-------------+
| 172.17.8.101 | node-to-node mesh |   up  | 17:54:00 | Established |
+--------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 address configured.

```
