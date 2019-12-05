---
title: Configuring BGP peers
description: Configure BGP peering for public cloud and on-premises deployments with full mesh, node-specific peering, ToR and/or Calico route reflectors.
canonical_url: 'https://docs.projectcalico.org/v3.9/networking/bgp'
---

### Big picture

Configure border gateway protocol (BGP) peering with network infrastructure to distribute routing information.

### Value

{{site.prodname}} nodes can exchange routing information over BGP to enable reachability for {{site.prodname}} networked workloads without the need for encapsulation.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Node resource**
- **BGPConfiguration resource**
- **BGPPeer resources**
  - **Global peer**
  - **Node-specific peer**

### Concepts

#### BGP

**BGP** is a standard protocol for exchanging routing information between two routers in a network. Each router running BGP has one or more BGP peers - other routers which they are communicating with over BGP. You can configure {{site.prodname}} nodes to peer with each other, with route reflectors, and with top-of-rack (ToR) routers.

#### Common BGP topologies

There are many ways to configure a BGP network depending on your environment. Here are some common ways it is done with {{site.prodname}}.

#### Topologies for public cloud

{{site.prodname}}’s default behavior is to create a full-mesh of internal BGP (iBGP) connections where each node peers with each other node. This design works great for small and medium-size deployments (< 100 nodes) in public cloud, but can hit performance bottlenecks at around 100 nodes.

To build large clusters in public cloud, BGP route reflectors can be used to reduce the number of BGP peerings used on each node. In this model, some nodes act as route reflectors and are configured to establish a full mesh amongst themselves. Other nodes are then configured to peer with a subset of those route reflectors.

You can also run {{site.prodname}} on public cloud without BGP or route reflectors using {{site.prodname}}’s VXLAN cross subnet capabilities. For more information, see [Configure overlay networking]({{site.baseurl}}/{{page.version}}/networking/vxlan-ipip).

#### Topologies for on-premises deployments

In on-premises deployments, you control the physical infrastructure, and can configure {{site.prodname}} to peer directly with it. Typically, this involves disabling {{site.prodname}}’s default full-mesh behavior and instead telling {{site.prodname}} to peer with your L3 ToR router. There are many ways to build an on-premises BGP network. How you configure your autonomous systems is up to you - {{site.prodname}} works well with both iBGP and eBGP configurations. 

Depending on your topology, you may also consider using BGP route reflectors within each rack. However, this is typically only needed if the number of nodes in each L2 domain is large (> 100).

For a deeper look at common on-premises deployment models, see [Calico over IP Fabrics]({{site.baseurl}}/{{page.version}}reference/architecture/design/l2-interconnect-fabric).

### Before you begin...

You must have installed and configured `calicoctl`.

### How to

- [Disable the default BGP node-to-node mesh](#disable-the-default-bgp-node-to-node-mesh)
- [Configure a global BGP peer](#configure-a-global-bgp-peer)
- [Configure a per-node BGP peer](#configure-a-per-node-bgp-peer)
- [Configure a node to act as a route reflector](#configure-a-node-to-act-as-a-route-reflector)
- [View BGP peering status for a node](#view-bgp-peering-status-for-a-node)
- [Change the global AS number](#change-the-global-as-number)
- [Change a particular node’s AS number](#change-a-particular-node's-as-number)

#### Disable the default BGP node-to-node mesh

The default **node-to-node BGP mesh** must be turned off to enable other BGP topologies. To do this, modify the default **BGP configuration** resource.

Run the following command to disable the BGP full-mesh:

```
calicoctl patch bgpconfiguration default -p '{"spec": {"nodeToNodeMeshEnabled": “false”}}'
```

>**Note**: If the default BGP configuration resource does not exist, you will need to create it first. See [BGP configuration]({{site.baseurl}}/{{page.version}}/reference/resources/bgpconfig) for more information.
{: .alert .alert-info}

#### Configure a global BGP peer

Global BGP peers apply to all nodes in your cluster. This is useful if your network topology includes BGP speakers that will be peered with every {{site.prodname}} node in your deployment.

The following example creates a global BGP peer that configures every {{site.prodname}} node to peer with 192.20.30.40 in AS 64567.

```
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: my-global-peer
spec:
  peerIP: 192.20.30.40
  asNumber: 64567
```
#### Configure a per-node BGP peer

Per-node BGP peers apply to one or more nodes in the cluster. You can choose which nodes either by specifying the node’s name exactly, or using a label selector.

The following example creates a BGP peer that configures every {{site.prodname}} node with the label rack: rack-1 to peer with 192.20.30.40 in AS 64567

```
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: rack1-tor
spec:
  peerIP: 192.20.30.40
  asNumber: 64567
  nodeSelector: rack == ‘rack-1’
```
#### Configure a node to act as a route reflector

{{site.prodname}} nodes can be configured to act as route reflectors. To do this, you must provide each node you want to act as a route reflector with a cluster ID - typically an unused IPv4 address.

To configure a node to be a route reflector with cluster ID 244.0.0.1, you can run the following command.

```
calicoctl patch node my-node -p '{"spec": {“bgp”: {"routeReflectorClusterID": “244.0.0.1”}}}'
```

It is likely that you will want to label this node to indicate that it is a route reflector, allowing it to be easily selected by a BGPPeer resource. You can do this with kubectl. For example:

```
kubectl label node my-node route-reflector=true
```
Now it is easy to configure route reflector nodes to peer with each other and other non-route-reflector nodes using label selectors. As an example:

```
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: peer-with-route-reflectors
spec:
  nodeSelector: all()
  peerSelector: route-reflector == ‘true’
```

#### View BGP peering status for a node

You can use calicoctl to view the current status of a particular node’s BGP connections. This is a useful way to confirm configuration is behaving as desired.

Run the following command on the node you with to inspect to view the current state:

```
sudo calicoctl node status
```
It will return a table listing all of the neighbors and their current status. Successful peerings will be listed as Established.

>**Note**: This command communicates with the local {{site.prodname}} agent and thus must be executed on the node whose status you are attempting to view.
{: .alert .alert-info}

#### Change a particular node's AS number

You can configure an AS for a particular node by modifying the node object using calicoctl. For example, the following command changes the node named node-1 to belong to AS 64514.

```
calicoctl patch node node-1 -p '{"spec": {"bgp": {“asNumber”: “64513”}}}'
```
### Above and beyond

- [Node resource]({{site.baseurl}}/{{page.version}}/reference/resources/node)
- [BGP configuration resource]({{site.baseurl}}/{{page.version}}/reference/resources/bgpconfig)
- [BGP peer resource]({{site.baseurl}}/{{page.version}}/reference/resources/bgppeer)
