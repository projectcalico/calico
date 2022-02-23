---
title: Configure BGP peering
description: Configure BGP peering with full mesh, node-specific peering, ToR, and/or Calico route reflectors.
canonical_url: '/networking/bgp'
---

### Big picture

Configure BGP (Border Gateway Protocol) between Calico nodes or peering with network infrastructure to distribute routing information.

### Value

{{site.prodname}} nodes can exchange routing information over BGP to enable reachability for {{site.prodname}} networked workloads (Kubernetes pods or OpenStack VMs). In an on-premises deployment this allows you to make your workloads first-class citizens across the rest of your network. In public cloud deployments, it provides an efficient way of distributing routing information within your cluster, and is often used in conjunction with IPIP overlay or cross-subnet modes.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Node resource**
- **BGPConfiguration resource**
- **BGPPeer resources**
  - **Global peer**
  - **Node-specific peer**

### Concepts

#### BGP

**BGP** is a standard protocol for exchanging routing information between routers in a network. Each router running BGP has one or more **BGP peers** - other routers which they are communicating with over BGP. You can think of {{site.prodname}} networking as providing a virtual router on each of your nodes. You can configure {{site.prodname}} nodes to peer with each other, with route reflectors, or with top-of-rack (ToR) routers.

#### Common BGP topologies

There are many ways to configure a BGP network depending on your environment. Here are some common ways it is done with {{site.prodname}}.

#### Full-mesh

When BGP is enabled, {{site.prodname}}’s default behavior is to create a **full-mesh** of internal BGP (iBGP) connections where each node peers with each other. This allows {{site.prodname}} to operate over any L2 network, whether public cloud or private cloud, or, if IPIP is [configured]({{site.baseurl}}/networking/vxlan-ipip), to operate as an overlay over any network that does not block IPIP traffic. {{site.prodname}} does not use BGP for VXLAN overlays.

>**Note**: Most public clouds support IPIP. The notable exception is Azure, which blocks IPIP traffic. So if you want to run Calico as an overlay network in Azure, you must [configure {{site.prodname}} to use VXLAN]({{site.baseurl}}/networking/vxlan-ipip).
{: .alert .alert-info}

Full-mesh works great for small and medium-size deployments of say 100 nodes or less, but at significantly larger scales full-mesh becomes less efficient, and we recommend using route reflectors.

#### Route reflectors

To build large clusters of internal BGP (iBGP), **BGP route reflectors** can be used to reduce the number of BGP peerings used on each node. In this model, some nodes act as route reflectors and are configured to establish a full mesh amongst themselves. Other nodes are then configured to peer with a subset of those route reflectors (typically 2 for redundancy), reducing the total number BGP peering connections compared to full-mesh.

#### Top of Rack (ToR)

In **on-premises deployments**, you can configure {{site.prodname}} to peer directly with your physical network infrastructure. Typically, this involves disabling {{site.prodname}}’s default full-mesh behavior, and instead peer {{site.prodname}} with your L3 ToR routers. There are many ways to build an on-premises BGP network. How you configure your BGP is up to you - {{site.prodname}} works well with both iBGP and eBGP configurations, and you can effectively treat {{site.prodname}} like any other router in your network design.

Depending on your topology, you may also consider using BGP route reflectors within each rack. However, this is typically needed only if the number of nodes in each L2 domain is large (> 100).

For a deeper look at common on-premises deployment models, see [Calico over IP Fabrics]({{ site.baseurl }}/reference/architecture/design/l2-interconnect-fabric).

### Before you begin...

[calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install) must be installed and configured.

### How to
>**Note**: Significantly changing {{site.prodname}}'s BGP topology, such as changing from full-mesh to peering with ToRs, may result in temporary loss of pod network connectivity during the reconfiguration process. It is recommended to only make such changes during a maintenance window.
{: .alert .alert-danger}

- [Configure a global BGP peer](#configure-a-global-bgp-peer)
- [Configure a per-node BGP peer](#configure-a-per-node-bgp-peer)
- [Configure a node to act as a route reflector](#configure-a-node-to-act-as-a-route-reflector)
- [Disable the default BGP node-to-node mesh](#disable-the-default-bgp-node-to-node-mesh)
- [Change from node-to-node mesh to route reflectors without any traffic disruption](#change-from-node-to-node-mesh-to-route-reflectors-without-any-traffic-disruption)
- [View BGP peering status for a node](#view-bgp-peering-status-for-a-node)
- [Change the default global AS number](#change-the-default-global-as-number)
- [Change AS number for a particular node](#change-as-number-for-a-particular-node)

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
  nodeSelector: rack == 'rack-1'
```
#### Configure a node to act as a route reflector

{{site.prodname}} nodes can be configured to act as route reflectors. To do this, each node that you want to act as a route reflector must have a cluster ID - typically an unused IPv4 address.

To configure a node to be a route reflector with cluster ID 244.0.0.1, run the following command.

```
calicoctl patch node my-node -p '{"spec": {"bgp": {"routeReflectorClusterID": "244.0.0.1"}}}'
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
  peerSelector: route-reflector == 'true'
```

>**Note**: Adding `routeReflectorClusterID` to a node spec will remove it from the node-to-node mesh immediately, tearing down the
>          existing BGP sessions. Adding the BGP peering will bring up new BGP sessions. This will cause a short (about 2 seconds)
>          disruption to dataplane traffic of workloads running in the nodes where this happens. To avoid this, make sure no
>          workloads are running on the nodes, by provisioning new nodes or by running `kubectl drain` on the node (which may
>          itself cause a disruption as workloads are drained).
{: .alert .alert-info}

#### Disable the default BGP node-to-node mesh

The default **node-to-node BGP mesh** may be turned off to enable other BGP topologies. To do this, modify the default **BGP configuration** resource.

Run the following command to disable the BGP full-mesh:

```
calicoctl patch bgpconfiguration default -p '{"spec": {"nodeToNodeMeshEnabled": false}}'
```

>**Note**: If the default BGP configuration resource does not exist, you need to create it first. See [BGP configuration]({{ site.baseurl }}/reference/resources/bgpconfig) for more information.
{: .alert .alert-info}

>**Note**: Disabling the node-to-node mesh will break pod networking until/unless you configure replacement BGP peerings using BGPPeer resources.
>          You may configure the BGPPeer resources before disabling the node-to-node mesh to avoid pod networking breakage.
{: .alert .alert-danger}

#### Change from node-to-node mesh to route reflectors without any traffic disruption

Switching from node-to-node BGP mesh to BGP route reflectors involves tearing down BGP sessions and bringing up new ones. This causes a short
dataplane network disruption (of about 2 seconds) for workloads running on the nodes in the cluster. In order to avoid this, you may provision
route reflector nodes and bring their BGP sessions up before tearing down the node-to-node mesh sessions.

Follow these steps to do so:

1. [Provision new nodes to be route reflectors.](#configure-a-node-to-act-as-a-route-reflector) The nodes [should not be schedulable](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/)
and they should have `routeReflectorClusterID` in their spec. These won't be part of the existing
node-to-node BGP mesh, and will be the route reflectors when the mesh is disabled. These nodes should also have a label like
`route-reflector` in order to select them for the BGP peerings. [Alternatively](https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/),
you can drain workloads from existing nodes in your cluster by running `kubectl drain <NODE>` in order to configure them to be route reflectors,
but this will cause a disruption on the workloads on those nodes as they are drained.

2. Also set up a [BGPPeer](#configure-a-node-to-act-as-a-route-reflector) spec to configure route reflector nodes to peer with each other and other non-route-reflector nodes
using label selectors.

3. Wait for these peerings to be established. This can be [verified](#view-bgp-peering-status-for-a-node) by running `sudo calicoctl node status` on the nodes. Alternatively, you can create a [`CalicoNodeStatus` resource]({{site.baseurl}}/reference/resources/caliconodestatus) to get BGP session status for the node.

4. [Disable the BGP node-to-node mesh for the cluster.](#disable-the-default-bgp-node-to-node-mesh)

5. If you did drain workloads from the nodes or created them as unschedulable, mark the nodes as schedulable again (e.g. by running `kubectl uncordon <NODE>`).

#### View BGP peering status for a node

Create a [CalicoNodeStatus resource]({{site.baseurl}}/reference/resources/caliconodestatus) to monitor BGP session status for the node.

Alternatively, you can run the `calicoctl node status` command on a given node to learn more about its BGP status.

>**Note**: This command communicates with the local {{site.prodname}} agent, so you must execute it on the node whose status you are attempting to view.
{: .alert .alert-info}

#### Change the default global AS number

By default, all Calico nodes use the 64512 autonomous system, unless a per-node AS has been specified for the node. You can change the global default for all nodes by modifying the default **BGPConfiguration** resource. The following example command sets the global default AS number to **64513**.

```
calicoctl patch bgpconfiguration default -p '{"spec": {"asNumber": "64513"}}'
```

>**Note**: If the default BGP configuration resource does not exist, you need to create it first. See [BGP configuration]({{ site.baseurl }}/reference/resources/bgpconfig) for more information.
{: .alert .alert-info}

#### Change AS number for a particular node

You can configure an AS for a particular node by modifying the node object using `calicoctl`. For example, the following command changes the node named **node-1** to belong to **AS 64514**.

```
calicoctl patch node node-1 -p '{"spec": {"bgp": {"asNumber": "64514"}}}'
```

### Above and beyond

- [Node resource]({{ site.baseurl }}/reference/resources/node)
- [BGP configuration resource]({{ site.baseurl }}/reference/resources/bgpconfig)
- [BGP peer resource]({{ site.baseurl }}/reference/resources/bgppeer)
