> ![warning](../../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../../README.md) main page.

# BGP Configuration

This document describes the commands available in calicoctl for managing BGP.
It covers configuration of:

-  Global default node AS Number
-  The full node-to-node mesh
-  Global BGP Peers
-  Node-specific BGP Peers

The global default node AS Number is the AS Number used by the BGP agent on a
Calico node when it has not been explicitly specified.  Setting this value
simplifies configuration when your network topology allows all of your Calico
nodes to use the same AS Number.

The full node-to-node mesh option provides a mechanism to automatically 
configure peering between all Calico nodes.  When enabled, each Calico node
automatically sets up a BGP peering with every other Calico node in the
network.  By default this is enabled.  However, the full node-to-node mesh is
only useful for small scale deployments and where all Calico nodes are on the
same L2 network.  We generally expect the full node-to-node mesh to be disabled
and explicit BGP peering configured.

Explicit BGP peers may be configured globally or for a particular node.

A global BGP peer is a BGP agent that peers with every Calico node in the 
network.  A typical use case for a global peer might be a mid-scale
deployment where all of the Calico nodes are on the same L2 network and are
each peering with the same Route Reflector (or set of Route Reflectors).

At scale, different network topologies come in to play.  For example, in the 
[AS Per Rack model](http://docs.projectcalico.org/en/latest/l3-interconnectFabric.html#the-as-per-rack-model)
discussed in the main Project Calico documentation, each Calico node peers with
a Route Reflector in the Top of Rack (ToR) switch.  In this case the BGP
peerings are configured on a per-node basis (i.e. these are node-specific
peers).  In the AS Per Rack model, each Calico node in a rack will be
configured with a node-specific peering to the ToR Route Reflector.


### Configuring the default node AS number

When creating a Calico node, you can optionally specify an AS number to use for
the node.  If no AS number if specified, the node will use the global default
value.

Use the `calicoctl bgp default-node-as` command to set the global default AS
number.  If no value is configured, the default AS number is 64511.

If all of your Calico nodes are within the same AS, but you require a
different AS number to be used (e.g because you are peering with a border
router), changing the default AS number to the value you require eliminates
the need to explicitly set it on a per Calico node basis.  For more
complicated topologies where you are explicitly setting the AS number on each
node, the default value will not be used and therefore using this command is
not necessary.

#### Example

To set the default AS number to 64512, run the following calicoctl command on
any node:

	$ calicoctl config set defaultNodeASNumber 64512
	
To view the current default value, run the following command:

	$ calicoctl config view defaultNodeASNumber
	64512
	

### Disabling the full node-to-node BGP mesh

If you are explicitly configuring the BGP topology for your Calico network, 
you may wish to disable the full node-to-node mesh.  Use the
`calicoctl config set` command to disable or re-enable the mesh.

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

	$ calicoctl config view nodeToNodeMesh
    COMPONENT   SCOPE    HOSTNAME   NAME             VALUE   
    bgp         global              nodeToNodeMesh   on      

### Configuring a global BGP peer

If your network topology includes BGP speakers that will be peered with *every* 
Calico node in your deployment, you can use the resource management commands to
set up the peering on your Calico nodes.  We refer to these as global peers 
because they peer with every Calico node.

Two situations where global BGP peer configuration is useful are when adding
a border router that is peering into a full node-to-node mesh, or configuring
a Calico network that uses one or two route reflectors to provide moderate
scale-out capabilities.  In the latter case, each Calico node would peer to
each of the Route Reflectors and the full node-to-node mesh would be
disabled.

#### Example

To add a global BGP peer at IP address 192.20.30.40 with AS number 64567 use the
`calicoctl create` command passing in the resource description of the peer indicating
a scope of "global":

	$ bin/calicoctl create -f bgppeer.yaml
    
    bgppeer.yaml
    ============
    
    apiVersion: v1
    kind: bgpPeer
    metadata:
      scope: global
      peerIP: 192.20.30.40
    spec:
      asNumber: 64567

To remove a global BGP peer that was configured with IP address 192.20.30.40 
(the AS number is not required when deleting) run the following command on any
node:

	$ calicoctl delete bgpPeer 192.20.30.40 --scope=global

To view the current list of global peers run the following command on any node:

    $ calicoctl get bgpPeer --scope=global
    SCOPE    PEERIP         HOSTNAME   ASN     
    global   192.20.30.40              64567   


### Configuring a node specific BGP peer

If your network topology requires specific peerings for each Calico node, you 
can use the `calicoctl create` commands to set up the peers specific to
each Calico node by specifying a scope of `node` and indicating which node
it belongs to by specifying the hostname.  We refer to these as node specific peers.

Configuring node specific peers is necessary when the BGP topology is more
complicated and requires different peerings on different nodes.  For example,
the
[AS per rack model](http://docs.projectcalico.org/en/latest/l3-interconnectFabric.html?highlight=tor#the-as-per-rack-model)
or
[AS per Compute Server model](http://docs.projectcalico.org/en/latest/l3-interconnectFabric.html?highlight=tor#the-as-per-compute-server-model)
described in the Project Calico documentation.

#### Example

To add a BGP peer at IP address aa:bb::ff with AS number 64514,
peering with Calico node "Node1", run the following command from the "Node1"
command line:

	$ bin/calicoctl create -f bgppeer.yaml
    
    bgppeer.yaml
    ============
    
    apiVersion: v1
    kind: bgpPeer
    metadata:
      scope: node
      hostname: Node1
      peerIP: aa:bb::ff
    spec:
      asNumber: 64514

To remove a BGP peer that was configured with IP address aa:bb::ff (the AS 
number is not required), peering with Calico node "Node1", run the following
command from the "Node1" command line:

	$ calicoctl delete bgpPeer aa:bb::ff --scope=node --hostname=Node1

To view the current list of node specific peers that are configured to peer
with Calico node "Node1", run the following command from the "Node1" command
line:

    $ bin/calicoctl get bgpPeer --scope=node
    SCOPE   PEERIP      HOSTNAME   ASN      
    node    aa:bb::ff   Node1      64514    

### Checking the status of the BGP peers

To display the status of all BGP peerings for a specific node, use the 
`calicoctl node status` command.  This displays the status of all BGP peers for
that node - this includes the peers that are automatically configured as part
of the full node-to-node mesh and the explicitly configured global peers and
node specific peers.

The `calicoctl node status` command must be run on the specific node.

Understanding the status of the BGP peerings is a useful first step in
diagnosing why routes may not be advertised across your network resulting in
incorrect connectivity between your workloads.

#### Example

To check the status of the peerings on Calico node "Node1", run
the following command from the "Node1" command line:

	Node1$ calicoctl status
	calico-node container is running. Status: Up 13 minutes

	IPv4 BGP status
	+--------------+-------------------+-------+----------+-------------+
	| Peer address |     Peer type     | State |  Since   |     Info    |
	+--------------+-------------------+-------+----------+-------------+
	| 172.17.42.21 | node-to-node mesh |   up  | 16:17:25 | Established |
	| 10.20.30.40  |       global      | start | 16:28:38 |   Connect   |
	|  192.10.0.0  |   node specific   | start | 16:28:57 |   Connect   |
	+--------------+-------------------+-------+----------+-------------+

	IPv6 BGP status
	+--------------+-------------------+-------+----------+-------------+
	| Peer address |     Peer type     | State |  Since   |     Info    |
	+--------------+-------------------+-------+----------+-------------+
	|   aa:bb::ff  | node-to-node mesh |   up  | 16:17:26 | Established |
	+--------------+-------------------+-------+----------+-------------+

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/general/bgp.md?pixel)](https://github.com/igrigorik/ga-beacon)
