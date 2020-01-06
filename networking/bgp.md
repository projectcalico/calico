---
title: Configure BGP peering
description: Configure BGP peering for public cloud and on-premises deployments with full mesh, node-specific peering, ToR and/or Calico route reflectors.
canonical_url: '/networking/bgp'
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

**BGP** is a standard protocol for exchanging routing information between two routers in a network. Each router running BGP has one or more **BGP peers** - other routers which they are communicating with over BGP. You can configure {{site.prodname}} nodes to peer with each other, with route reflectors, and with top-of-rack (ToR) routers.

#### Common BGP topologies

There are many ways to configure a BGP network depending on your environment. Here are some common ways it is done with {{site.prodname}}.

#### Topologies for public cloud

{{site.prodname}}’s default behavior is to create a **full-mesh** of internal BGP (iBGP) connections where each node peers with each other. This design works great for small and medium-size deployments (< 100 nodes) in public cloud, but you can hit performance bottlenecks at around 100 nodes.

To build large clusters in public cloud, **BGP route reflectors** can be used to reduce the number of BGP peerings used on each node. In this model, some nodes act as route reflectors and are configured to establish a full mesh amongst themselves. Other nodes are then configured to peer with a subset of those route reflectors.

You can also run {{site.prodname}} on public cloud without BGP or route reflectors using {{site.prodname}}’s **VXLAN cross subnet capabilities**. For more information, see [Configure overlay networking]({{ site.baseurl }}/networking/vxlan-ipip).

#### Topologies for on-premises deployments

In **on-premises deployments**, you control the physical infrastructure, so you can configure {{site.prodname}} to peer directly with it. Typically, this involves disabling {{site.prodname}}’s default full-mesh behavior, and instead peer {{site.prodname}} with your L3 ToR router. There are many ways to build an on-premises BGP network. How you configure your autonomous systems is up to you - {{site.prodname}} works well with both iBGP and eBGP configurations. 

Depending on your topology, you may also consider using BGP route reflectors within each rack. However, this is typically needed only if the number of nodes in each L2 domain is large (> 100).

For a deeper look at common on-premises deployment models, see [Calico over IP Fabrics]({{ site.baseurl }}/reference/architecture/design/l2-interconnect-fabric).

### Before you begin...

[calicoctl]({{ site.baseurl }}/getting-started/calicoctl/install) must be installed and configured.

### How to

- [Disable the default BGP node-to-node mesh](#disable-the-default-bgp-node-to-node-mesh)
- [Configure a global BGP peer](#configure-a-global-bgp-peer)
- [Configure a per-node BGP peer](#configure-a-per-node-bgp-peer)
- [Configure a node to act as a route reflector](#configure-a-node-to-act-as-a-route-reflector)
- [View BGP peering status for a node](#view-bgp-peering-status-for-a-node)
- [Change the default global AS number](#change-the-default-global-as-number)
- [Change AS number for a particular node](#change-as-number-for-a-particular-node)

#### Disable the default BGP node-to-node mesh

The default **node-to-node BGP mesh** must be turned off to enable other BGP topologies. To do this, modify the default **BGP configuration** resource.

Run the following command to disable the BGP full-mesh:

```
calicoctl patch bgpconfiguration default -p '{"spec": {"nodeToNodeMeshEnabled": “false”}}'
```

>**Note**: If the default BGP configuration resource does not exist, you need to create it first. See [BGP configuration]({{ site.baseurl }}/reference/resources/bgpconfig) for more information.
{: .alert .alert-info}

#### Configure a global BGP peer

Global BGP peers apply to all nodes in your cluster. This is useful if your network topology includes BGP speakers that will be peered with every {{site.prodname}} node in your deployment.

The following example creates a global BGP peer that configures every {{site.prodname}} node to peer with **192.20.30.40** in AS **64567**.

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

Per-node BGP peers apply to one or more nodes in the cluster. You can choose which nodes by specifying the node’s name exactly, or using a label selector.

The following example creates a BGPPeer that configures every {{site.prodname}} node with the label, **rack: rack-1** to peer with **192.20.30.40** in AS **64567**.

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

{{site.prodname}} nodes can be configured to act as route reflectors. To do this, each node that you want to act as a route reflector must have a cluster ID - typically an unused IPv4 address.

To configure a node to be a route reflector with cluster ID 244.0.0.1, run the following command.

```
calicoctl patch node my-node -p '{"spec": {“bgp”: {"routeReflectorClusterID": “244.0.0.1”}}}'
```

Typically, you will want to label this node to indicate that it is a route reflector, allowing it to be easily selected by a BGPPeer resource. You can do this with kubectl. For example:

```
kubectl label node my-node route-reflector=true
```
Now it is easy to configure route reflector nodes to peer with each other and other non-route-reflector nodes using label selectors. For example:

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

You can use `calicoctl` to view the current status of a particular node’s BGP connections. This is useful for confirming that your configuration is behaving as desired.

Run the following command on the node you want to view the current state:

```
sudo calicoctl node status
```
A table that lists all of the neighbors and their current status is displayed. Successful peerings are listed as, **Established**.

>**Note**: This command communicates with the local {{site.prodname}} agent, so you must execute it on the node whose status you are attempting to view.
{: .alert .alert-info}

#### Change the default global AS number

By default, all Calico nodes use the 64512 autonomous system, unless a per-node AS has been specified for the node. You can change the global default for all nodes by modifying the default **BGPConfiguration** resource. The following example command sets the global default AS number to **64513**.

```
calicoctl patch bgpconfiguration default -p '{"spec": {"asNumber": “64513”}}'
```

>**Note**: If the default BGP configuration resource does not exist, you need to create it first. See [BGP configuration]({{ site.baseurl }}/reference/resources/bgpconfig) for more information.
{: .alert .alert-info}

#### Change AS number for a particular node

You can configure an AS for a particular node by modifying the node object using `calicoctl`. For example, the following command changes the node named **node-1** to belong to **AS 64514**.

```
calicoctl patch node node-1 -p '{"spec": {"bgp": {“asNumber”: “64514”}}}'
```
### Above and beyond

- [Node resource]({{ site.baseurl }}/reference/resources/node)
- [BGP configuration resource]({{ site.baseurl }}/reference/resources/bgpconfig)
- [BGP peer resource]({{ site.baseurl }}/reference/resources/bgppeer)
