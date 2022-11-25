---
title: Calico over Ethernet fabrics
description: Understand the interconnect fabric options in a Calico network. 
canonical_url: '/reference/architecture/design/l2-interconnect-fabric'
---

Any technology that is capable of transporting IP packets can be used as the interconnect fabric in a {{site.prodname}} network. This means that the standard tools used to transport IP, such as MPLS and Ethernet can be used in a {{site.prodname}} network.

The focus of this article is on Ethernet as the interconnect network. Most at-scale cloud operators have converted to IP fabrics, and that infrastructure will work for {{site.prodname}} as well. However, the concerns that drove most of those operators to IP as the interconnection network in their pods are largely ameliorated by {{site.prodname}}, allowing Ethernet to be viably considered as a {{site.prodname}} interconnect, even in large-scale deployments.

### Concerns over Ethernet at scale

It has been acknowledged by the industry for years that, beyond a certain size, classical Ethernet networks are unsuitable for production deployment. Although there have been {% include open-new-window.html text='multiple' url='https://en.wikipedia.org/wiki/Provider_Backbone_Bridge_Traffic_Engineering' %} {% include open-new-window.html text='attempts' url='https://web.archive.org/web/20150923231827/https://www.cisco.com/web/about/ac123/ac147/archived_issues/ipj_14-3/143_trill.html' %} {% include open-new-window.html text='to address' url='https://en.wikipedia.org/wiki/Virtual_Private_LAN_Service' %} these issues, the scale-out networking community has largely abandoned Ethernet for anything other than providing physical point-to-point links in the networking fabric. The principle reasons for Ethernet failures at large scale are:

- Large numbers of *endpoints* ([note 1](#note-1))

   Each switch in an Ethernet network must learn the path to all Ethernet endpoints that are connected to the Ethernet network. Learning this amount of state can become a substantial task when we are talking about hundreds of thousands of *endpoints*.

- High rate of *churn* or change in the network

   With that many endpoints, most of them being ephemeral (such as virtual machines orcontainers), there is a large amount of *churn* in the network. That load of re-learning paths can be a substantial burden on the control plane processor of most Ethernet switches.

- High volumes of broadcast traffic

   As each node on the Ethernet network must use Broadcast packets to locate peers, and many use broadcast for other purposes, the resultant packet replication to each and every endpoint can lead to *broadcast storms* in large Ethernet networks, effectively consuming most, if not all resources in the network and the attached endpoints.

- Spanning tree

   Spanning tree is the protocol used to keep an Ethernet network from forming loops. The protocol was designed in the era of smaller, simpler networks, and it has not aged well. As the number of links and interconnects in an Ethernet network goes up, many implementations of spanning tree become more *fragile*. Unfortunately, when spanning tree fails in an Ethernet network, the effect is a catastrophic loop or partition (or both) in the network, and, in most cases, difficult to troubleshoot or resolve.

Although many of these issues are crippling at *VM scale* (tens of thousands of endpoints that live for hours, days, weeks), they will be absolutely lethal at *container scale* (hundreds of thousands of endpoints that live for seconds, minutes, days).

If you weren't ready to turn off your Ethernet data center network before this, I bet you are now. Before you do, however, let's look at how {{site.prodname}} can mitigate these issues, even in very large deployments.

### How does {{site.prodname}} tame the Ethernet daemons?

First, let's look at how {{site.prodname}} uses an Ethernet interconnect fabric. It's important to remember that an Ethernet network *sees* nothing on the other side of an attached IP router, the Ethernet network just *sees* the router itself. This is why Ethernet switches can be used at Internet peering points, where large fractions of Internet traffic is exchanged. The switches only see the routers from the various ISPs, not those ISPs' customers' nodes. We leverage the same effect in {{site.prodname}}.

To take the issues outlined above, let's revisit them in a {{site.prodname}}
context.

- Large numbers of endpoints

    In a {{site.prodname}} network, the Ethernet interconnect fabric only sees the routers/compute servers, not the
    endpoint. In a standard cloud model, where there is tens of VMs per server (or hundreds of containers), this reduces the number of nodes that the Ethernet sees (and has to learn) by one to two orders
    of magnitude. Even in very large pods (say twenty thousand servers), the Ethernet network would still only see a few tens of thousands of endpoints. Well within the scale of any competent data center
    Ethernet top of rack (ToR) switch.

- High rate of churn

    In a classical Ethernet data center fabric, there is a *churn* event each time an endpoint is created,
    destroyed, or moved. In a large data center, with hundreds of thousands of endpoints, this *churn* could run into tens of events per second, every second of the day, with peaks easily in the hundreds or thousands of events per second. In a {{site.prodname}} network, however, the *churn* is very low. The only event that would lead to *churn*
    orders of magnitude more than what is normally experienced), there would only be two thousand events per **day**. Any switch that can not handle that volume of change in the network should not be used
    for any application.

- High volume of broadcast traffic

    Because the first (and last) hop for any traffic in a {{site.prodname}} network is an IP hop, and IP hops terminate
    broadcast traffic, there is no endpoint broadcast network in the Ethernet fabric, period. In fact, the only broadcast traffic that should be seen in the Ethernet fabric is the ARPs of the compute servers locating each other. If the traffic pattern is fairly consistent, the steady-state ARP rate should be almost zero. Even in a pathological case, the ARP rate should be well within normal accepted boundaries.

- Spanning tree

    Depending on the architecture chosen for the Ethernet fabric, it may even be possible to turn off spanning tree. However, even if it is left on, due to the reduction in node count, and reduction in churn, most competent spanning tree implementations should be able to handle the load without stress.

With these considerations in mind, it should be evident that an Ethernet connection fabric in {{site.prodname}} is not only possible, it is practical and should be seriously considered as the interconnect fabric for a {{site.prodname}}
network.

As mentioned in the IP fabric post, an IP fabric is also quite feasible for {{site.prodname}}, but there are more considerations that must be taken into account. The Ethernet fabric option has fewer architectural considerations in its design.

### A brief note about Ethernet topology

As mentioned elsewhere in the {{site.prodname}} documentation, because {{site.prodname}} can use most of the standard IP tooling, some interesting options regarding fabric topology become possible.

We assume that an Ethernet fabric for {{site.prodname}} would most likely be constructed as a *leaf/spine* architecture. Other options are possible, but the *leaf/spine* is the predominant architectural model in use in
scale-out infrastructure today.

Because {{site.prodname}} is an IP routed fabric, a {{site.prodname}} network can use {% include open-new-window.html text='ECMP' url='https://en.wikipedia.org/wiki/Equal-cost_multi-path_routing' %} to distribute traffic across multiple links (instead of using Ethernet techniques such as MLAG). By leveraging ECMP load balancing on the {{site.prodname}} compute servers, it is possible to build the fabric out of multiple *independent* leaf/spine planes using no technologies other than IP routing in the {{site.prodname}} nodes, and basic Ethernet switching in the interconnect fabric. These planes would operate completely independently and could be designed such that they would not share a fault domain. This would allow for the catastrophic failure of one (or more) plane(s) of Ethernet interconnect fabric without the loss of the pod (the failure would just decrease the amount of interconnect bandwidth in the pod). This is a gentler failure mode than the pod-wide IP or Ethernet failure that is possible with today's designs.

You might find this {% include open-new-window.html text='Facebook blog
post' url='https://code.facebook.com/posts/360346274145943/introducing-data-center-fabric-the-next-generation-facebook-data-center-network/' %} on their fabric approach interesting. A graphic to visualize the idea is shown below.

![Ethernet spine planes]({{site.baseurl}}/images/l2-spine-planes.png)

The diagram does not show the endpoints in this diagram, and the endpoints would be unaware of anything in the fabric (as noted above).

In this diagram, each ToR is segmented into four logical switches (possibly by using 'port VLANs'), ([note 2](#note-2)) and each compute server has a connection to each of those logical switches. We will identify those logical switches by their color. Each ToR would then have a blue, green, orange, and red logical switch. Those 'colors' would be members of a given *plane*, so there would be a blue plane, a green plane, an orange plane, and a red plane. Each plane would have a dedicated spine switch. and each ToR in a given spine would be connected to its spine, and only its spine.

Each plane would constitute an IP network, so the blue plane would be 2001:db8:1000::/36, the green would be 2001:db8:2000::/36, and the orange and red planes would be 2001:db8:3000::/36 and 2001:db8:4000::/36 respectively ([note 3](#note-3)).

Each IP network (plane) requires it's own BGP route reflectors. Those route reflectors need to be peered with each other within the plane, but the route reflectors in each plane do not need to be peered with one another. Therefore, a fabric of four planes would have four route reflector meshes. Each compute server, border router, *etc.* would need
to be a route reflector client of at least one route reflector in each plane, and very preferably two or more in each plane.

The following diagram visualizes the route reflector environment.

![route-reflector]({{site.baseurl}}/images/l2-rr-spine-planes.png)

These route reflectors could be dedicated hardware connected to the spine switches (or the spine switches themselves), or physical or virtual route reflectors connected to the necessary logical leaf switches (blue, green, orange, and red). That may be a route reflector running on a compute server and connected directly to the correct plane link, and not routed through the vRouter, to avoid the chicken and egg problem that would occur if the route reflector were "behind" the {{site.prodname}} network.

Other physical and logical configurations and counts are, of course, possible, this is just an example.

The logical configuration would then have each compute server would have an address on each plane's subnet, and announce its endpoints on each subnet. If ECMP is then turned on, the compute servers would distribute the load across all planes.

If a plane were to fail (say due to a spanning tree failure), then only that one plane would fail. The remaining planes would stay running.

#### Footnotes

#### Note 1

In this document (and in all {{site.prodname}} documents) we tend to use the term *endpoint* to refer to a virtual machine, container, appliance, bare metal server, or any other entity that is connected to a {{site.prodname}} network. If we are referring to a specific type of endpoint, we will call that out (such as referring to the behavior of VMs as distinct from containers).

#### Note 2

We are using logical switches in this example. Physical ToRs could also be used, or a mix of the two (say 2 logical switches hosted on each physical switch).

#### Note 3 

We use IPv6 here purely as an example. IPv4 would be configured similarly. 
