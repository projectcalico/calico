===================================
 IP Interconnect Fabrics in Calico
===================================
----------------------------------------------------
 Where large-scale IP networks and hardware collide
----------------------------------------------------

Calico provides an end--to--end IP network that interconnects the end
points [#end_points]_ in a scale--out or cloud environment. To do that, it needs
an *interconnect fabric* to provide the physical networking layer on
which Calico operates [#interconnect_fabric]_

While Calico is designed to work with any underlying interconnect
fabric that can support IP traffic, the fabric that has the least
considerations attached to its implementation is an Ethernet fabric as
discussed in our earlier `technical note
<http://project-calico.readthedocs.org/en/latest/l2-interconnectFabric.html>`__.

In most cases, the Ethernet fabric is the appropriate choice, but
there are infrastructures 
where L3 (an IP fabric) has already been deployed, or will be deployed,
and it makes sense for Calico to operate in those environments.

However, since Calico is, itself, a routed infrastructure, there are
more engineering, architecture, and operations considerations that have
to be weighed when running Calico with an IP routed interconnection
fabric. We will briefly outline those in the rest of this post. That
said, Calico operates equally well with Ethernet or IP interconnect
fabrics.

Background
==========
Basic Calico architecture overview
----------------------------------

A description of the Calico architecture can be found
`here <http://www.projectcalico.org/technical/architecture/>`__.
However, a brief discussion of the routing and data paths is useful for
the discussion.

In a Calico network, each compute server acts as a router for all of the
end points that are hosted on that compute server. We call that function
a vRouter. The data path is provided by the Linux kernel, the control
plane by a BGP protocol server, and management plane by Calico's
on--server agent, *felix*.

Each end--point can only communicate through it's local vRouter, and the
first and last *hop* in any Calico packet flow is an IP router hop
through a vRouter. Each vRouter announces all of the end points it is
attached to to all the other vRouters and other routers on the
infrastructure fabric, using BGP, usually with BGP route reflectors to
increase scale. A discussion of why we use BGP can be found in the `Why
BGP? <http://www.projectcalico.org/why-bgp/>`__ blog post.

Access control lists (ACLs) enforce security (and other) policy as
directed by whatever cloud orchestrator is in use. There are other
components in the Calico architecture, but they are irrelevant to the
interconnect network fabric discussion.

Overview of current common IP scale--out fabric architectures
-------------------------------------------------------------

There are two approaches to building an IP fabric for a scale--out
infrastructure. However, all of them, to date, have assumed that the
edge router in the infrastructure is the top of rack (TOR) switch. In
the Calico model, that function is pushed to the compute server itself.

Furthermore, in most current virtualized environments, the actual
end point is not addressed by the fabric. If it is a VM, it is usually
encapsulated in an overlay, and if it is a container, it may be
encapsulated in an overlay, or NATed by some form of proxy, such as is
done in the `weave <http://www.weave.works/>`__ project network model,
or the router in standard `docker <http://www.docker.io/>`__ networking.

The two approaches are outlined below, in this technical note, we will
cover the second option, as it is more common in the scale--out
world.  If there is interest in the first approach, please contact
Project Calico, and we can discuss, and if there is enough interest,
maybe we will do another technical note on that approach.  If you know
of other approaches in use, we would be happy to host a guest
technical note.

#. The routing infrastructure is based on some form of IGP. Due to the
   limitations in scale of IGP networks (see the `why
   bgp post <http://www.projectcalico.org/why-bgp/>`__ for discussion of
   this topic.  The project Calico team does not believe that using an
   IGP to distribute end--point reachability information will
   adequitely scale in a Calico environment.  However, it is possible
   to use a combination of IGP and BGP in the interconnect fabric,
   where an IGP communicates the path to the *next--hop* router (in
   Calico, this is often the destination compute server) and BGP is
   used to distribute the actual next--hop for a given end--point.
   This is a valid model, and, in fact is the most common approach in
   a widely distributed IP network (say a carrier's backbone network).  The
   design of these networks is somewhat complex though, and will not
   be addressed further in this technical note. [#igp_punt]_

#. The other model, and the one that this note concerns it self with,
   is one where the routing infrastructure is based entirely on BGP.
   In this model, the IP network is "tight enough" or has a small
   enough diameter that BGP can be used to distribute end point
   routes, and the paths to the next--hops for those routes is known
   to all of the routers in the network (in a Calico network this
   includes the compute servers).  This is the network model that this
   note will address.

BGP--only interconnect fabrics
==============================
   
There are multiple methods to build a BGP--only interconnect fabric.
We will focus on two models, each with two widely viable variations.
There are other options, and we will briefly touch on why we didn't
include some of them in the `Other Options`_ appendix.

The two methods are:

#. A BGP fabric where each of the TOR switches (and their subsidiary
   compute servers) are a unique 
   `Autonomous System (AS)`_ and they are interconnected via either an
   Ethernet switching plane provided by the spine switches in a
   `leaf/spine`_
   architecture, or via a set of spine switches, each of which is also
   a unique AS.  We'll refer to this as the *AS per rack* model.  This
   model is detailed in `this IETF working group draft`_.  

#. A BGP fabric where each of the compute servers is a unique AS, and
   the TOR switches make up a transit AS.  We'll refer to this as the
   *AS per server* model.

.. _`Autonomous System (AS)`: http://en.wikipedia.org/wiki/Autonomous_System_(Internet)
.. _leaf/spine:
   http://bradhedlund.com/2012/10/24/video-a-basic-introduction-to-the-leafspine-data-center-networking-fabric-design/
.. _`this IETF working group draft`:
   https://tools.ietf.org/html/draft-ietf-rtgwg-bgp-routing-large-dc

Each of these models can either have an Ethernet or IP spine.  In the
case of an Ethernet spine, each spine switch provides an isolated
Ethernet connection *plane* as in the Calico Ethernet interconnect
fabric model and each TOR switch is connected to each spine switch.

Another model is where each spine switch is a unique AS, and each TOR
switch BGP peers with each spine switch.  In both cases, the TOR
switches use ECMP to load--balance traffic between all available spine
switches.

Some BGP network design considerations
--------------------------------------

Contrary to popular opinion, BGP is actually a fairly simple protocol.
For example, the BGP configuration on a Calico compute server is
approximately sixty lines long, not counting comments. The perceived
complexity is due to the things that you can *do* with BGP. Many uses of
BGP involve complex policy rules, where the behavior of BGP can be
modified to meet technical (or business, financial, political, *etc.*)
requirements. A default Calico network does not venture into those
areas, [4]_ and therefore is fairly straight forward.

That said, there are a few design rules for BGP that need to be kept in
mind when designing an IP fabric that will interconnect nodes in a
Calico network. These BGP design requirements *can* be worked around, if
necessary, but doing so takes the designer out of the standard BGP
*envelope* and should only be done by an implementer who is *very*
comfortable with advanced BGP design.

These considerations are:

AS continuity
  or *AS puddling*  Any router in an AS *must* be able
  to communicate with any other router in that same AS without
  transiting another AS.

Next hop behavior
  By default BGP routers do not change the *next hop* of a route if it
  is peering with another router in it's same AS.  The inverse is also
  true, a BGP router will set itself as the *next hop* of a route if
  it is peering with a router in another AS.

Route reflection
  All BGP routers in a given AS must *peer* with all the other routers
  in that AS.  This is referred to a *complete BGP mesh*.  This can
  become problematic as the number of routers in the AS scales up.
  The use of *route reflectors* reduce the need for the complete BGP
  mesh.  However, route reflectors also have scaling considerations.

Endpoints
  In a Calico network, each endpoint is a route.  Hardware networking
  platforms are constrained by the number of routes they can learn.
  This is usually in range of 10,000's or 100m,000's of routes.  Route
  aggregation can help, but that is usually dependent on the
  capabilities of the scheduler used by the orchestration software
  (*e.g.* OpenStack).

A deeper discussion of these considerations can be found in the `IP
Fabric Design Considerations`_ appendix.

The designs discussed below address these considerations.

The *AS Per Rack* model
-----------------------

This model is the closest to the model suggested by the `IETF's
Routing Area Working Group draft on BGP use in data centers`_.  

.. _`IETF's Routing Area Working Group draft on BGP use in data centers`:
   https://tools.ietf.org/html/draft-ietf-rtgwg-bgp-routing-large-dc

As mentioned earlier, there are two versions of this model, one with
an set of Ethernet planes interconnecting the ToR switches, and the
other where the core planes are also routers.  The following diagrams
may be useful for the discussion

.. figure:: _static/l3-interconnectFabric/l3-fabric-diagrams-as-rack-l2-spine.*
   :align: center
   :alt: A diagram showing the AS per rack model using Ethernet as the
	 spine interconnect

   This diagram shows the *AS per rack model* where the ToR switches
   are physically meshed via a set of Ethernet switching planes.

.. figure:: _static/l3-interconnectFabric/l3-fabric-diagrams-as-rack-l3-spine.*
   :align: center
   :alt: A diagram showing the AS per rack model using routers as the
	 spine interconnect

   This diagram shows the *AS per rack model* where the ToR switches
   are physically meshed via a set of discrete BGP spine routers, each
   in their own AS.

   

Some standard IP fabric architectures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Calico solution does not dictate an interconnect technology or
architecture, as long as it can transport IP traffic. That said, we have
identified a potential Ethernet solution as noted in `this
post <http://www.projectcalico.org/using-ethernet-as-the-interconnect-fabric-for-a-calico-installation/>`__
and we are now going to propose two possible IP fabric designs. Others
are possible, and if you have developed any other designs that you find
useful, we would love to feature their ideas in a guest blog.

Both of these models use similar diagrams, so a quick key/description is
warranted here.

-  Devices are outlined in a box. Functions are indicated within that
   box.
-  Blue rectangles are Ethernet switching functions. In the case of an
   L3 switch, the blue rectangle provides an L2 switched connection
   between other devices and the switch's routing function.
-  Circles are BGP routers. Different colors indicate different AS's.
-  Solid blue lines are L2 links.
-  Solid orange lines are L3 links.
-  Dashed orange links are BGP iBGP peering sessions. eBGP peering
   sessions are point--to--point over the L3 link itself.
-  Diamonds are BGP route reflection functions. They are shown *half on
   and half off* a switch as the function may reside on the ToR switch,
   or on a server/guest within the rack.
-  Triangles are end--points.

Both of these models are based on the `IETF Internet Draft on BGP in the
data
center <https://tools.ietf.org/html/draft-ietf-rtgwg-bgp-routing-large-dc-00#section-5.2>`__.
They differ in how many ASes are used in the network. They do have some
commonality, in that both have IP links between the end points and the
compute server vRouter. This is the same as in the `Ethernet
fabric <http://www.projectcalico.org/using-ethernet-as-the-interconnect-fabric-for-a-calico-installation/>`__.

Another commonality is that both models use an Ethernet spine
infrastructure. While it is possible to run an L3 spine, it introduces
complexity around AS puddling. If you remember from earlier, all iBGP
routers must have direct reachability to one another, and must not pass
through another AS for that connectivity. Since spine switches, in the
classical leaf--spine architecture are *not* connected to one another,
but are only connected to the leaves, it is difficult to build a L3
spine that does not introduce AS puddling or unwanted paths. Therefore,
the spines act as independent interconnection switches for the L3
leaves.

Both of these models should scale to 100's of leaf switches. The exact
number is dependent on the capability of the leaf switches in use. If
this number is too small, a Calico implementation should look at using
the Ethernet fabric option, or using an L3--based spine architecture.
That will be covered briefly in a follow--up post. As noted just above,
this is a more *involved* architecture, so it is best approached after
reading the blog post that discusses it, and having a good grasp of BGP
design techniques. Reach out to the Project Calico team if you have
questions about this.

A final common point is that the L3 leaf switches use ECMP to distribute
their traffic between all available spine switches.

AS per rack model
~~~~~~~~~~~~~~~~~

The following diagram shows a two rack pod implementing this model.

.. figure:: l3-fabric-l2r-l2s.png
   :alt: AS per rack

   AS per rack

This is a direct adaptation of the IETF BGP for data center model. Each
compute server connected to a leaf or spine switch (usually this is all
the servers in a given rack) is in an Ethernet segment which has a
routing interface in the switch. The compute servers and the ToR switch
are in the same autonomous system, and each rack is its own unique AS.

One or more (preferably two) route reflectors are deployed in the rack,
either on the ToR itself, or on one or more compute servers in the rack.
It would be best if those route reflectors were *not* in a VM, as there
would be a *chicken and egg* problem with the route reflector needing to
be reachable before it could be connected to the fabric. If a container
is used to deploy the route reflector, it should be in the root network
name--space for that reason.

Traffic between two compute servers within a given rack would traverse
the ToR switch, but would not be routed on the ToR switch (the compute
servers would be the only routers in the path).

Traffic that is exiting the rack (or inbound to the rack) would be
routed via the ToR as the next hop router for the compute server.

Each ToR would have an eBGP peering to all other ToR switches in the
pod, as well as the border routers, over the L2 spine switches. Route
reflection would not be used, as these are eBGP sessions.

AS per compute server
~~~~~~~~~~~~~~~~~~~~~

The AS per rack model is a logical outgrowth of the fact that, until
Calico, the first routing--capable aggregation point was the ToR switch.
However, with Calico, the individual compute servers are the first
routing aggregation point.

Therefore, it is possible to take the same approach as above, but push
the AS boundary to the individual compute server. This is also possible
as the 4--byte AS number space has over 92,000,000 AS numbers reserved
for private use. A diagram may help.

.. figure:: l3-fabric-l3r-l2s.png
   :alt: AS per compute server

   AS per compute server
The primary difference here is that there are no route reflectors in
use. Each compute server is eBGP peered with it's ToR switch(es). In
turn, the ToR switches are in eBGP peerings with one another, as in the
earlier architecture.

One benefit is that the server provisioning system does not need to
understand rack geography (which servers are in which racks) to assign
the AS number to a given compute server, as each compute server has a
unique AS number. This may be easier to automate.

Recommendation
==============

The Project Calico team urges potential Calico users to consider the
Ethernet fabric, due to its scale and simplicity. However, if an IP
fabric is required, we recommend, at this time, the AS per rack model.
If a Calico user is interested in the AS per compute server, the Project
Calico team would be very interested in discussing the deployment of
that model.

Appendix
========
Other Options
-------------

IP Fabric Design Considerations
-------------------------------

AS puddling
~~~~~~~~~~~

The first consideration is that an AS must be kept contiguous. This
means that any two nodes in a given AS must be able to communicate
without traversing any other AS. If this rule is not observed, the
effect is often referred to as *AS puddling* and the network will *not*
function correctly.

A corollary of that rule is that any two administrative regions that
share the same AS number, are in the same AS, even if that was not the
desire of the designer. BGP has no way of identifying if an AS is local
or foreign other than the AS number. Therefore re--use of an AS number
for two *networks* that are not directly connected, but only connected
through another *network* or AS number will not work without a lot of
policy changes to the BGP routers.

Another corollary of that rule is that a BGP router will not propagate a
route to a peer if the route has an AS in it's path that is the same AS
as the peer. This prevents loops from forming in the network. The effect
of this prevents two routers in the same AS from transiting another
router (either in that AS or not).

Next hop behavior
~~~~~~~~~~~~~~~~~

Another consideration is based on the differences between iBGP and eBGP.
BGP operates in two modes, if two routers are BGP peers, but share the
same AS number, then they are considered to be in an *internal* BGP (or
iBGP) peering relationship. If they are members of different AS's, then
they are in an *external* or eBGP relationship.

BGP's original design model was that all BGP routers within a given AS
would know how to get to one another (via static routes, IGP [5]_
routing protocols, or the like), and that routers in different ASs would
not know how to reach one another unless they were directly connected.

Based on that design point, routers in an iBGP peering relationship
assume that they do not transit traffic for other iBGP routers in a
given AS (i.e. A can communicate with C, and therefore will not need to
route through B), and therefore, do not change the *next hop* attribute
in BGP [6]_.

A router with an eBGP peering, on the other hand, assumes that it's eBGP
peer will not know how to reach the next hop route, and then will
substitute its own address in the next hop field. This is often referred
to as *next hop self*.

In the Calico `Ethernet
fabric <http://www.projectcalico.org/using-ethernet-as-the-interconnect-fabric-for-a-calico-installation/>`__
model, all of the compute servers (the routers in a Calico network) are
directly connected over one or more Ethernet network(s) and therefore
are directly reachable. In this case, a router in the Calico network
does not need to set *next hop self* within the Calico fabric.

In the IP interconnect fabric, however, there are other routers
in--between the Calico routers, meaning that the Calico routers will not
have direct connectivity between themselves. Therefore, the BGP
configuration of those intermediate routers (usually either the TOR
and/or Spine switches) will need to set *next hop self* either by being
configured as eBGP routers in the `multi-AS
model <https://tools.ietf.org/html/draft-ietf-rtgwg-bgp-routing-large-dc-00#section-5.2>`__
as discussed in the [Multiple AS model][] section, or by setting the
*next hop self* attribute in the [Single AS model][] approach.

Route reflection
~~~~~~~~~~~~~~~~

As mentioned above, BGP expects that all of the iBGP routers in a
network can see (and speak) directly to one another, this is referred to
as a *BGP full mesh*. In small networks this is not a problem, but it
does become interesting as the number of routers increases. For example,
if you have 99 BGP routers in an AS and wish to add one more, you would
have to configure the peering to that new router on each of the 99
existing routers. Not only is this a problem at configuration time, it
means that each router is maintaining 100 protocol adjacencies, which
can start being a drain on constrained resources in a router. While this
might be *interesting* at 100 routers, it becomes an impossible task
with 1000's or 10,000's of routers (the potential size of a Calico
network).

Conveniently, large scale/Internet scale networks solved this problem
almost 20 years ago by deploying `BGP route
reflection <https://tools.ietf.org/html/rfc1966>`__. This is a technique
supported by almost all BGP routers today. In a large network, a number
of route reflectors [7]_ are evenly distributed and each iBGP router is
*peered* with one or more route reflectors (usually 2 or 3). Each route
reflector can handle 10's or 100's of route reflector clients (in
Calico's case, the compute server), depending on the route reflector
being used. Those route reflectors are, in turn, peered with each other.
This means that there are an order of magnitude less route reflectors
that need to be completely meshed, and each route reflector client is
only configured to peer to 2 or 3 route reflectors. This is much easier
to manage.

Other route reflector architectures are possible, but those are beyond
the scope of this document.

Endpoints
~~~~~~~~~

The final consideration is the number of endpoints in a Calico network.
In the `Ethernet fabric
case <http://www.projectcalico.org/using-ethernet-as-the-interconnect-fabric-for-a-calico-installation/>`__,
the number of endpoints is not constrained by the interconnect fabric,
as the interconnect fabric does not *see* the actual endpoints, it only
*sees* the actual vRouters, or compute servers. This is not the case in
an IP fabric, however. IP networks forward by using the destination IP
address in the packet, which, in Calico's case, is the destination
endpoint. That means that the IP fabric nodes (ToR switches and/or spine
switches, for example) must know the routes to each endpoint in the
network. They learn this by participating as route reflector clients in
the BGP mesh, just as the Calico vRouter/compute server does.

However, unlike a compute server which has a relatively unconstrained
amount of memory, a physical switch is either memory constrained, or
quite expensive. This means that the physical switch has a limit on how
many *routes* it can handle. The current industry standard for modern
commodity switches is in the range of 128,000 routes. This means that,
without other routing *tricks*, such as aggregation, a Calico
installation that uses an IP fabric will be limited to the routing table
size of it's constituent network hardware, with a reasonable upper limit
today of 128,000 endpoints.



.. [#end_points]
   In Calico's terminology, an end point is an IP address and interface.
   It could refer to a VM, a container, or even a process bound to an IP
   address running on a bare metal server.

.. [#interconnect_fabric]
   This interconnect fabric provides the connectivity between the Calico
   (v)Router (in almost all cases, the compute servers) nodes, as well
   as any other elements in the fabric (*e.g.* bare metal servers,
   border routers, and appliances).

.. [#igp_punt]
   If there is interest in a discussion of this approach, please let
   us know.  The Project Calico team could either arrange a
   discussion, or if there was enough interest, publish a follow--up
   tech note.

.. [4]
   However those tools are available if a given Calico instance needs to
   utilize those policy constructs.

.. [5]
   An Interior Gateway Protocol is a local routing protocol that does
   not cross an AS boundary. The primary IGPs in use today are OSPF and
   IS--IS. While complex iBGP networks still use IGP routing protocols,
   a data center is normally a fairly simple network, even if it has
   many routers in it. Therefore, in the data center case, the use of an
   IGP can often be disposed of.

.. [6]
   A Next hop is an attribute of a route announced by a routing
   protocol. In simple terms a route is defined by a *target*, or the
   destination that is to be reached, and a *next hop*, which is the
   next router in the path to reach that target. There are many other
   characteristics in a route, but those are well beyond the scope of
   this post.

.. [7]
   A route reflector may be a physical router, a software appliance, or
   simply a BGP daemon. It only processes routing messages, and does not
   pass actual data plane traffic. However, some route reflectors are
   co--resident on regular routers that do pass data plane traffic.
   While they may sit on one platform, the functions are distinct.
