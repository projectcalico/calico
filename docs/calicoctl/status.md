<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# User reference for 'calicoctl status' commands

This sections describes the `calicoctl status` commands.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
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
   or as a `global` BGP peer (See the [`calicoctl bgp` reference](./bgp.md) for 
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
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calicoctl/status.md?pixel)](https://github.com/igrigorik/ga-beacon)
