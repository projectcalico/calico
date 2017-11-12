---
title: Configuring BGP Peers
---

This document describes the commands available in `calicoctl` for managing BGP.  It
is intended primarily for users who are running on private cloud
and would like to peer {{site.prodname}} with their underlying infrastructure.

This document covers configuration of:

-  Global default node AS Number
-  The full node-to-node mesh
-  Global BGP Peers
-  Node-specific BGP Peers

### Concepts

**AS Number**

The global default node AS Number is the AS Number used by the BGP agent on a
{{site.prodname}} node when it has not been explicitly specified.  Setting this value
simplifies configuration when your network topology allows all of your {{site.prodname}}
nodes to use the same AS Number.

**Node-to-Node Mesh**

The full node-to-node mesh option provides a mechanism to automatically
configure peering between all {{site.prodname}} nodes.  When enabled, each {{site.prodname}} node
automatically sets up a BGP peering with every other {{site.prodname}} node in the
network.  By default this is enabled.

The full node-to-node mesh provides a simple mechanism for auto-configuring
the BGP network in small scale deployments (say 50 nodes - although this limit
is not set in stone and {{site.prodname}} has been deployed with over 100 nodes in a full
mesh topology).

For large-scale deployments, or for deployments where you require a more specific
BGP topology (e.g. peering with ToR switches) the full node-to-node mesh should be
disabled and explicit BGP peers configured for your {{site.prodname}} nodes.  A BGP peer may 
be configured in your {{site.prodname}} network as a Global BGP Peer or a Per-Node BGP Peer.

**Global BGP Peers**

A global BGP peer is a BGP agent that peers with every {{site.prodname}} node in the
network.  A typical use case for a global peer might be a mid-scale
deployment where all of the {{site.prodname}} nodes are on the same L2 network and are
each peering with the same Route Reflector (or set of Route Reflectors).

**Per-Node BGP Peers**

At scale, different network topologies come in to play.  For example, in the
[AS per Rack model]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric#the-as-per-rack-model)
discussed in the reference material, each {{site.prodname}} node peers with
a Route Reflector in the Top of Rack (ToR) switch.  In this case the BGP
peerings are configured on a per-node basis (i.e. these are node-specific
peers).  In the AS Per Rack model, each {{site.prodname}} node in a rack will be
configured with a node-specific peering to the ToR Route Reflector.

### Configuring the default node AS number

When creating a {{site.prodname}} node, you can optionally specify an AS number to use for
the node.  If no AS number if specified, the node will use the global default
value.

See [Example](#example) to set the global default AS number.
to set the global default AS number. If no value is configured, the default AS number is 64512.

If all of your {{site.prodname}} nodes are within the same AS, but you require a
different AS number to be used (e.g because you are peering with a border
router), changing the default AS number to the value you require eliminates
the need to explicitly set it on a per {{site.prodname}} node basis.  For more
complicated topologies where you are explicitly setting the AS number on each
node, the default value will not be used and therefore using this command is
not necessary.

> **Note**: Prior to version 2.0.0, `calicoctl` and `calico/node` set the global default
> AS number to 64511. Updating your deployment from a pre-2.0.0 version to use
> the 2.0.0+ `calicoctl` and `calico/node` container images will not affect the
> global value that was previously set.
{: .alert .alert-info}

### Disabling the full node-to-node BGP mesh

If you are explicitly configuring the BGP topology for your {{site.prodname}} network,
you may wish to disable the full node-to-node mesh. See
[Example](#example) 
for instructions to change the `nodeToNodeMesh` global BGP setting.

If you are building your network from scratch and do not need the full
node-to-node mesh we recommend turning off the mesh before configuring your
nodes.  If you are updating your network from a full-mesh topology to a
different topology (e.g. to start using a cluster of route reflectors to
increase scaling), configure the appropriate peers before disabling the mesh
to ensure continuity of service.

#### Example

To turn off the full BGP node-to-node mesh, or to modify the global AS number,
run the following command on any node:

```
# Get the current bgpconfig settings
$ calicoctl get bgpconfig -o yaml > bgp.yaml

# Modify nodeToNodeMeshEnabled to true or false
# -or-
# modify the asNumber to appropropriate integer
$ vim bgp.yaml

# Replace the current bgpconfig settings
$ calicoctl replace -f bgp.yaml
```

### Configuring a global BGP peer

If your network topology includes BGP speakers that will be peered with *every*
{{site.prodname}} node in your deployment, you can use the `calicoctl` resource management
commands to set up the peering on your {{site.prodname}} nodes.  We refer to these types
of peer as global peers because they are configured in {{site.prodname}} once (globally)
and {{site.prodname}} will peer every {{site.prodname}} node with these peers.

Two situations where global BGP peer configuration is useful are (1) when adding
a border router that is peering into a full node-to-node mesh, or (2) configuring
a {{site.prodname}} network that uses one or two route reflectors to provide moderate
scale-out capabilities.  In the latter case, each {{site.prodname}} node would peer to
each of the Route Reflectors and the full node-to-node mesh would be
disabled.

#### Example

To add a global BGP peer at IP address 192.20.30.40 with AS number 64567 run
the following command on any node:

```
$ cat << EOF | calicoctl create -f -
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: bgppeer-global-3040
spec:
  peerIP: 192.20.30.40
  asNumber: 64567
EOF
```

To remove a global BGP peer that was configured with IP address 192.20.30.40
(the AS number is not required when deleting) run the following command on any
node:

	$ calicoctl delete bgpPeer 192.20.30.40 --scope=global

To view the current list of global peers run the following command on any node:

```
$ calicoctl get bgpPeer --scope=global
SCOPE    PEERIP         NODE   ASN
global   192.20.30.40          64567
```

### Configuring a node specific BGP peer

If your network topology requires specific peerings for each {{site.prodname}} node, you
can use the `calicoctl` resource management commands to set up the peers
specific to a {{site.prodname}} nodes.  We refer to these as node specific peers.

Configuring node specific peers is necessary when the BGP topology is more
complicated and requires different peerings on different nodes.  For example,
the
[AS per Rack model]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric#the-as-per-rack-model)
or
[AS per Compute Server model]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric#the-as-per-compute-server-model)
described in the reference material.

#### Example

To add a BGP peer at IP address aa:bb::ff with AS number 64514,
peering with {{site.prodname}} node "node1", run the following command on any node:

```
$ cat << EOF | calicoctl create -f -
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: bgppeer-node-aabbff
spec:
  peerIP: aa:bb::ff
  node: node1
  asNumber: 64514
EOF
```

To remove a BGP peer that was configured with IP address aa:bb::ff (the AS
number is not required), peering with {{site.prodname}} node "node1", run the following
command from any node:

	$ calicoctl delete bgpPeer aa:bb::ff --scope=node --node=node1

To view the current list of node specific peers that are configured to peer
with {{site.prodname}} node "node1", run the following command from any node:

```
$ calicoctl get bgpPeer --node=node1
SCOPE   PEERIP      NODE    ASN
node    aa:bb::ff   node1   64514
```

### Checking the status of the BGP peers

To display the status of all BGP peerings for a specific node, use the
`calicoctl node status` command.  This displays the status of all BGP peers for
that node - this includes the peers that are automatically configured as part
of the full node-to-node mesh and the explicitly configured global peers and
node specific peers.

Understanding the status of the BGP peerings is a useful first step in
diagnosing why routes may not be advertised across your network resulting in
incorrect connectivity between your workloads.

#### Example

To check the status of the peerings on {{site.prodname}} node "node1", run
the following command from the "node1" command line:

```
$ sudo calicoctl node status
Calico process is running.

IPv4 BGP status
+--------------+-------------------+-------+----------+-------------+
| PEER ADDRESS |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+--------------+-------------------+-------+----------+-------------+
| 172.17.8.102 | node-to-node mesh | up    | 23:30:04 | Established |
| 10.20.30.40  |       global      | start | 16:28:38 |   Connect   |
|  192.10.0.0  |   node specific   | start | 16:28:57 |   Connect   |
+--------------+-------------------+-------+----------+-------------+

IPv6 BGP status
+--------------+-------------------+-------+----------+-------------+
| PEER ADDRESS |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+--------------+-------------------+-------+----------+-------------+
| aa:bb::ff    | node-to-node mesh | up    | 16:17:26 | Established |
+--------------+-------------------+-------+----------+-------------+
```
