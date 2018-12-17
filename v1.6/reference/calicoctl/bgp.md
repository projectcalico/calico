---
title: calicoctl bgp
canonical_url: 'https://docs.projectcalico.org/v3.4/reference/calicoctl/resources/bgppeer'
---

This sections describes the `calicoctl bgp` commands.

These commands can be used to manage the global BGP configuration, including:
 - global BGP peers (the BGP speakers that peer with every Calico node in the
   network)
 - default values to use for the AS number
 - whether a full BGP mesh is required between all of the Calico nodes

Calico node-specific BGP configuration, such as having BGP peers specific to a
particular Calico node, is configured using the `calicoctl node` commands. You
can read about these commands in the [`calicoctl node` guide](node).

For an overview of BGP configuration, read the [BGP tutorial]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp), which
covers in more detail all available BGP related commands, including use cases.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl bgp' commands

Run `calicoctl bgp --help` to display the following help menu for the
calicoctl bgp commands.

```

Usage:
  calicoctl bgp peer add <PEER_IP> as <AS_NUM>
  calicoctl bgp peer remove <PEER_IP>
  calicoctl bgp peer show [--ipv4 | --ipv6]
  calicoctl bgp node-mesh [on|off]
  calicoctl bgp default-node-as [<AS_NUM>]


Description:
  Configure default global BGP settings for all nodes. Note: per-node settings
  will override these globals for that node.

Options:
 --ipv4    Show IPv4 information only.
 --ipv6    Show IPv6 information only.

```

## calicoctl bgp commands


### calicoctl bgp peer add \<PEER_IP\> as \<AS_NUM\>
This command is used to add a global BGP peer.

The command can be run on any machine that can access the etcd datastore, such
as a Calico node host.

Command syntax:

```
calicoctl bgp peer add <PEER_IP> as <AS_NUM>

    <PEER_IP>:  The IP address (IPv4 or IPv6) of the BGP peer
    <AS_NUM>:  The AS number of the BGP peer.
```

The peer is uniquely identified by the IP address, so if you add another peer
with the same IP address and different AS number, it will replace the previous
peer configuration.

Configuring a global peer instructs all Calico nodes in the deployment to
establish a peering using the specified peer IP address and AS number.  If the
AS number is the same as the AS number configured on the node, this will be an
iBGP connection, otherwise it will be an eBGP connection.

Examples:

```
$ calicoctl bgp peer add 192.0.2.10 as 64555

$ calicoctl bgp peer add 2001:0db8::1 as 64590
```

### calicoctl bgp peer remove \<PEER_IP\>
This command removes a global BGP peer that was previously added using
`bgp peer add <PEER IP> as <AS_NUM>`.

The peer is uniquely identified by the IP address it was added with.

Removing a global peer instructs all Calico nodes in the deployment to delete
the peering associated with the specified peer IP address.

The command can be run on any machine that can access the etcd datastore, such
as a Calico node host.

Command syntax:

```
calicoctl bgp peer remove \<PEER_IP\>

    <PEER_IP>:  The IP address (IPv4 or IPv6) of the BGP peer
```

Examples:

```
$ calicoctl bgp peer remove 192.0.2.10
BGP peer removed from global configuration

$ calicoctl bgp peer remove 2001:0db8::1
BGP peer removed from global configuration
```

### calicoctl bgp peer show
This command displays the current list of configured global BGP peers.

This command does not display the connection or protocol status of the peers.
If you want to view that information, use the [`calicoctl status`](status)
command.

The command can be run on any Calico node.

Command syntax:

```
calicoctl bgp peer show [--ipv4 | --ipv6]

    --ipv4:  Optional flag to show IPv4 peers only
    --ipv6:  Optional flag to show IPv6 peers only

    If neither --ipv4 nor --ipv6 are specified, all peers are displayed.    
```

Examples:

```
$ calicoctl bgp peer show
+----------------------+--------+
| Global IPv4 BGP Peer | AS Num |
+----------------------+--------+
| 192.0.2.10           | 64555  |
+----------------------+--------+
+----------------------+--------+
| Global IPv6 BGP Peer | AS Num |
+----------------------+--------+
| 2001:db8::1          | 64590  |
+----------------------+--------+

$ calicoctl bgp peer show --ipv4
+----------------------+--------+
| Global IPv4 BGP Peer | AS Num |
+----------------------+--------+
| 192.0.2.10           | 64555  |
+----------------------+--------+
```

### calicoctl bgp node-mesh
This command is used to view the status of, or enable and disable, the full
node-to-node BGP mesh.

When set to `on`, the Calico nodes automatically create a peering with all
other Calico nodes in the deployment.

In large deployments, you may want to set this value to `off` in order to
manage BGP peerings explicitly.

The command can be run on any Calico node.

Command syntax:

```
calicoctl bgp node-mesh [on|off]

    off:  Disable the node-to-node BGP mesh between all of the Calico nodes.
    on:  Enable the node-to-node BGP mesh between all of the Calico nodes.

    If no parameter is specified, this command displays the current status.
```

Examples:

```
$ calicoctl bgp node-mesh on

$ calicoctl bgp node-mesh off

$ calicoctl bgp node-mesh
off
```

### calicoctl bgp default
This command is used to view and set the default AS number used by Calico
nodes.

When a Calico node is started (see [`calicoctl node`](node) commands),
the default AS number is used to configure the BGP peerings if one has not
been explicitly specified in the `calicoctl node` command.

If any nodes are using the default AS number (i.e. an AS number was not
explicitly specified on the node), then changing the default value with the
following command will automatically trigger the nodes to peer using the
updated AS number.

The command can be run on any Calico node.

Command syntax:

```
calicoctl bgp default-node-as [<AS_NUM>]

    <AS_NUM>: AS number to set as the default for all Calico nodes.

    If no parameter is specified, this command displays the current value.
```

Examples:

```
$ calicoctl bgp default-node-as 64512

$ calicoctl bgp default-node-as
64512
```
