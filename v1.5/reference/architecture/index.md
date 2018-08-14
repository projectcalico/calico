---
title: Calico Architecture
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/architecture/'
---

This document discusses the various pieces of the Calico etcd-based
architecture, with a focus on what specific role each component plays in
the Calico network. This does not discuss the Calico etcd data model,
which also acts as the primary API into the Calico network.


# Components

Calico is made up of the following interdependent components:

-   [Felix](#felix), the primary Calico agent that runs on each
    machine that hosts endpoints.
-   The [Orchestrator plugin](#orchestrator-plugin),
    orchestrator-specific code that tightly integrates Calico into
    that orchestrator.
-   [etcd](#etcd), the data store.
-   [BIRD](#bgp-client-bird), a BGP client that
    distributes routing information.
-   [BGP Route Reflector (BIRD)](#bgp-route-reflector-bird), an optional BGP
    route reflector for higher scale.

The following sections break down each component in more detail.


## Felix

Felix is a daemon that runs on every machine that provides endpoints: in
most cases that means on nodes that host containers or VMs. It is
responsible for programming routes and ACLs, and anything else required
on the host, in order to provide the desired connectivity for the
endpoints on that host.

Depending on the specific orchestrator environment, Felix is responsible
for the following tasks:

#### Interface Management

Felix programs some information about interfaces into the kernel in
order to get the kernel to correctly handle the traffic emitted by that
endpoint. In particular, it will ensure that the host responds to ARP
requests from each workload with the MAC of the host, and will enable IP
forwarding for interfaces that it manages.

It also monitors for interfaces to appear and disappear so that it can
ensure that the programming for those interfaces is applied at the
appropriate time.

#### Route Programming

Felix is responsible for programming routes to the endpoints on its host
into the Linux kernel FIB (Forwarding Information Base) . This ensures that packets destined for those
endpoints that arrive on at the host are forwarded accordingly.

#### ACL Programming

Felix is also responsible for programming ACLs into the Linux kernel.
These ACLs are used to ensure that only valid traffic can be sent
between endpoints, and ensure that endpoints are not capable of
circumventing Calico's security measures. For more on this, see
the [security model description]({{site.baseurl}}/{{page.version}}/reference/security-model).

#### State Reporting

Felix is responsible for providing data about the health of the network.
In particular, it reports errors and problems with configuring its host.
This data is written into etcd, to make it visible to other components
and operators of the network.


## Orchestrator Plugin

Unlike Felix there is no single 'orchestrator plugin': instead, there
are separate plugins for each major cloud orchestration platform (e.g.
OpenStack, Kubernetes). The purpose of these plugins is to bind Calico
more tightly into the orchestrator, allowing users to manage the Calico
network just as they'd manage network tools that were built into the
orchestrator.

A good example of an orchestrator plugin is the Calico Neutron ML2
mechanism driver. This component integrates with Neutron's ML2 plugin,
and allows users to configure the Calico network by making Neutron API
calls. This provides seamless integration with Neutron.

The orchestrator plugin is responsible for the following tasks:

#### API Translation

The orchestrator will inevitably have its own set of APIs for managing
networks. The orchestrator plugin's primary job is to translate those
APIs into the Calico etcd data model to allow
Calico to perform the appropriate network programming.

Some of this translation will be very simple, other bits may be more
complex in order to render a single complex operation (e.g. live
migration) into the series of simpler operations the rest of the Calico
network expects.

#### Feedback

If necessary, the orchestrator plugin will provide feedback from the
Calico network into the orchestrator. Examples include: providing
information about Felix liveness; marking certain endpoints as failed if
network setup failed.



## etcd

etcd is a distributed key-value store that has a focus on consistency.
Calico uses etcd to provide the communication between components and as
a consistent data store, which ensures Calico can always build an
accurate network.

Depending on the orchestrator plugin, etcd may either be the master data
store or a lightweight mirror of a separate data store. For example, in
an OpenStack deployment, the OpenStack database is considered the
"source of truth" and etcd is used to mirror information about the
network to the other Calico components.

The etcd component is distributed across the entire deployment. It is
divided into two groups of machines: the core cluster, and the proxies.

For small deployments, the core cluster can be an etcd cluster of one
node (which would typically be co-located with the
[orchestrator plugin](#orchestrator-plugin) component). This deployment model is simple but provides no redundancy for etcd -- in the case of etcd failure the
[orchstrator plugin](#orchestrator-plugin) would have to rebuild the database which, as noted for OpenStack, will simply require that the plugin resynchronizes
state to etcd from the OpenStack database.

In larger deployments, the core cluster can be scaled up, as per the
[etcd admin guide](https://coreos.com/etcd/docs/latest/admin_guide.html#optimal-cluster-size).

Additionally, on each machine that hosts either a [Felix](#felix)
or a [plugin](#orchestrator-plugin), we run an etcd proxy. This reduces the load
on the core cluster and shields nodes from the specifics of the etcd
cluster. In the case where the etcd cluster has a member on the same
machine as a [plugin](#orchestrator-plugin), we can forgo the proxy on that
machine.

etcd is responsible for performing the following tasks:

#### Data Storage

etcd stores the data for the Calico network in a distributed,
consistent, fault-tolerant manner (for cluster sizes of at least three
etcd nodes). This set of properties ensures that the Calico network is
always in a known-good state, while allowing for some number of the
machines hosting etcd to fail or become unreachable.

This distributed storage of Calico data also improves the ability of the
Calico components to read from the database (which is their most common
operation), as they can distribute their reads around the cluster.

#### Communication

etcd is also used as a communication bus between components. We do this
by having the non-etcd components watch certain points in the keyspace
to ensure that they see any changes that have been made, allowing them
to respond to those changes in a timely manner. This allows the act of
committing the state to the database to cause that state to be programmed
into the network.



## BGP Client (BIRD)

Calico deploys a BGP client on every node that also hosts a [Felix](#felix). The role of the BGP client is to read routing state that [Felix](#felix) programs into the kernel and
distribute it around the data center.

In Calico, this BGP component is most commonly
[BIRD](http://bird.network.cz/), though any BGP client, such as [GoBGP](https://github.com/osrg/gobgp) that can draw
routes from the kernel and distribute them is suitable in this role.

The BGP client is responsible for performing the following task:

#### Route Distribution

When [Felix](#felix) inserts routes into the Linux kernel FIB,
the BGP client will pick them up and distribute them to the other nodes
in the deployment. This ensures that traffic is efficiently routed
around the deployment.


## BGP Route Reflector (BIRD)

For larger deployments, simple BGP can become a limiting factor because
it requires every BGP client to be connected to every other BGP client
in a mesh topology. This requires an increasing number of connections
that rapidly become tricky to maintain, due to the N^2 nature of the
increase.

For that reason, in larger deployments, Calico will deploy a BGP route
reflector. This component, commonly used in the Internet, acts as a
central point to which the BGP clients connect, preventing them from
needing to talk to every single BGP client in the cluster.

For redundancy, multiple BGP route reflectors can be deployed
seamlessly. The route reflectors are purely involved in the control of
the network: no endpoint data passes through them.

In Calico, this BGP component is also most commonly
[BIRD](http://bird.network.cz/), configured as a route reflector rather
than as a standard BGP client.

The BGP route reflector is responsible for the following task:

#### Centralized Route Distribution

When the [Calico BGP client](#bgp-client-bird) advertises routes
from its FIB to the route reflector, the route reflector advertises
those routes out to the other nodes in the deployment.
