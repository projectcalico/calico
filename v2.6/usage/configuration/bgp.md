---
title: Configuring BGP Peers
canonical_url: 'https://docs.projectcalico.org/v3.4/usage/configuration/bgp'
---

This document describes the commands available in `calicoctl` for managing BGP. It
is intended primarily for users who are running on private cloud
and would like to peer Calico with their underlying infrastructure.

This document covers configuration of:

-  Global default node AS Number
-  The full node-to-node mesh
-  Global BGP Peers
-  Node-specific BGP Peers

### Concepts

**AS Number**

The global default node AS Number is the AS Number used by the BGP agent on a
Calico node when it has not been explicitly specified.  Setting this value
simplifies configuration when your network topology allows all of your Calico
nodes to use the same AS Number.

**Node-to-Node Mesh**

The full node-to-node mesh option provides a mechanism to automatically
configure peering between all Calico nodes.  When enabled, each Calico node
automatically sets up a BGP peering with every other Calico node in the
network.  By default this is enabled.

The full node-to-node mesh provides a simple mechanism for auto-configuring
the BGP network in small scale deployments (say 50 nodes - although this limit
is not set in stone and Calico has been deployed with over 100 nodes in a full
mesh topology).

For large-scale deployments, or for deployments where you require a more specific
BGP topology (e.g. peering with ToR switches) the full node-to-node mesh should be
disabled and explicit BGP peers configured for your Calico nodes.  A BGP peer may 
be configured in your Calico network as a Global BGP Peer or a Per-Node BGP Peer.

**Global BGP Peers**

A global BGP peer is a BGP agent that peers with every Calico node in the
network.  A typical use case for a global peer might be a mid-scale
deployment where all of the Calico nodes are on the same L2 network and are
each peering with the same Route Reflector (or set of Route Reflectors).

**Per-Node BGP Peers**

At scale, different network topologies come in to play.  For example, in the
[AS per Rack model]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric#the-as-per-rack-model)
discussed in the reference material, each Calico node peers with
a Route Reflector in the Top of Rack (ToR) switch.  In this case the BGP
peerings are configured on a per-node basis (i.e. these are node-specific
peers).  In the AS Per Rack model, each Calico node in a rack will be
configured with a node-specific peering to the ToR Route Reflector.

### Configuring the default node AS number

When creating a Calico node, you can optionally specify an AS number to use for
the node.  If no AS number if specified, the node will use the global default
value.

Use the `calicoctl config set asNumber` command to set the global default AS
number.  If no value is configured, the default AS number is 64512.

If all of your Calico nodes are within the same AS, but you require a
different AS number to be used (e.g because you are peering with a border
router), changing the default AS number to the value you require eliminates
the need to explicitly set it on a per Calico node basis.  For more
complicated topologies where you are explicitly setting the AS number on each
node, the default value will not be used and therefore using this command is
not necessary.

> **Note**: Prior to version 2.0.0, `calicoctl` and `calico/node` set the global default
> AS number to 64511. Updating your deployment from a pre-2.0.0 version to use
> the 2.0.0+ `calicoctl` and `calico/node` container images will not affect the
> global value that was previously set.
{: .alert .alert-info}

#### Example

To set the default AS number to 64513, run the following calicoctl command on
any node:

	$ calicoctl config set asNumber 64513

To view the current default value, run the command without specifying an AS
number, the command will output the current value.

	$ calicoctl config get asNumber
	64513

To get the node configuration:

	$ calicoctl get node kube-node1 -o yaml
	- apiVersion: v1
	  kind: node
	  metadata:
	    name: kube-node1
	  spec:
	    bgp:
	      ipv4Address: 172.31.3.11/32

To set the local AS number to use for the node (just copy the retrieved 
configuration and add `asNumber` key under `spec/bgp`:

	$ calicoctl apply -f - <<EOF
	- apiVersion: v1
	  kind: node
	  metadata:
	    name: kube-node1
	  spec:
	    bgp:
	      asNumber: 65011
	      ipv4Address: 172.31.3.11/32
	EOF

### Disabling the full node-to-node BGP mesh

If you are explicitly configuring the BGP topology for your Calico network,
you may wish to disable the full node-to-node mesh.  Use the
`calicoctl config set nodeToNodeMesh` command to disable or re-enable the mesh.

If you are building your network from scratch and do not need the full
node-to-node mesh we recommend turning off the mesh before configuring your
nodes.  If you are updating your network from a full-mesh topology to a
different topology (e.g. to start using a cluster of route reflectors to
increase scaling), configure the appropriate peers before disabling the mesh
to ensure continuity of service.

#### Example

To turn off the full BGP node-to-node mesh run the following command on any
node:

	$ calicoctl config set nodeToNodeMesh off

If you need to turn the full BGP node-to-node mesh back on run the following
command on any node:

	$ calicoctl config set nodeToNodeMesh on

To view whether the BGP node-to-node mesh is on or off, enter the command
without specifying the parameter, the command will output the current state.

	$ calicoctl config get nodeToNodeMesh
	on


### Configuring a global BGP peer

If your network topology includes BGP speakers that will be peered with *every*
Calico node in your deployment, you can use the `calicoctl` resource management
commands to set up the peering on your Calico nodes.  We refer to these types
of peer as global peers because they are configured in Calico once (globally)
and Calico will peer every Calico node with these peers.

Two situations where global BGP peer configuration is useful are (1) when adding
a border router that is peering into a full node-to-node mesh, or (2) configuring
a Calico network that uses one or two route reflectors to provide moderate
scale-out capabilities.  In the latter case, each Calico node would peer to
each of the Route Reflectors and the full node-to-node mesh would be
disabled.

#### Example

To add a global BGP peer at IP address 192.20.30.40 with AS number 64567 run
the following command on any node:

```
$ cat << EOF | calicoctl create -f -
apiVersion: v1
kind: bgpPeer
metadata:
  peerIP: 192.20.30.40
  scope: global
spec:
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

If your network topology requires specific peerings for each Calico node, you
can use the `calicoctl` resource management commands to set up the peers
specific to a Calico nodes.  We refer to these as node specific peers.

Configuring node specific peers is necessary when the BGP topology is more
complicated and requires different peerings on different nodes.  For example,
the
[AS per Rack model]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric#the-as-per-rack-model)
or
[AS per Compute Server model]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric#the-as-per-compute-server-model)
described in the reference material.

#### Example

To add a BGP peer at IP address aa:bb::ff with AS number 64514,
peering with Calico node "node1", run the following command on any node:

```
$ cat << EOF | calicoctl create -f -
apiVersion: v1
kind: bgpPeer
metadata:
  peerIP: aa:bb::ff
  scope: node
  node: node1
spec:
  asNumber: 64514
EOF
```

To remove a BGP peer that was configured with IP address aa:bb::ff (the AS
number is not required), peering with Calico node "node1", run the following
command from any node:

	$ calicoctl delete bgpPeer aa:bb::ff --scope=node --node=node1

To view the current list of node specific peers that are configured to peer
with Calico node "node1", run the following command from any node:

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

To check the status of the peerings on Calico node "node1", run
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
