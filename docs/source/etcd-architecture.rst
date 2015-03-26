Calico etcd-based architecture
==============================

The current version of Calico is built around `etcd`_. etcd is a distributed,
consistent key value store for shared configuration and service discovery with
a focus on being simple, secure, fast, and reliable.

In Calico, etcd is used as the data store and communication mechanism for all
the Calico components. This data store contains all the information the various
Calico components to set up the Calico network.

This document discusses the various pieces of the Calico etcd-based
architecture, with a focus on what specific role each component plays in the
Calico network. This does not discuss the Calico etcd data model, which also
acts as the primary API into the Calico network: for more on that, see
:doc:`etcd-data-model`.

.. _etcd: https://github.com/coreos/etcd

Components
----------

Calico is made up of the following interdependent components:

- :ref:`calico-felix-component`, the primary Calico agent that runs on each
  machine that hosts endpoints.
- :ref:`calico-orchestrator-plugin`, orchestrator-specific code that tightly
  integrates Calico into that orchestrator.
- :ref:`calico-etcd-component`, running unmodified and used by the other
  components as a data store.
- :ref:`calico-bgp-component`, a BGP client that distributes routing
  information.
- :ref:`calico-bgp-rr-component`, an optional BGP route reflector for higher
  scale.

The following sections break down each component in more detail.


.. _calico-felix-component:

Felix
-----

Felix is the most important component in the Calico network: without it, no
network programming can be achieved. It is a daemon that runs on every machine
that provides endpoints: that means on nodes that host containers or VMs in
most cases.

Depending on the specific orchestrator environment, Felix is responsible for
some or all of the following tasks:

Interface Creation and Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In some environments, particularly containerized ones, Felix is responsible
for creating and managing network interfaces to its endpoints. This usually
involves creating and managing 'veth pairs': a pair of virtual ethernet
interfaces that behave as though they're connected together with a single
Ethernet cable.

In all cases, regardless of what kind of environment it runs in, Felix also
programs some other information about interfaces into the kernel. In
particular, it may enable `Proxy ARP`_, `Proxy NDP`_, and IP forwarding for
interfaces that it manages.

.. _Proxy ARP: http://en.wikipedia.org/wiki/Proxy_ARP
.. _Proxy NDP: http://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol

Route Programming
~~~~~~~~~~~~~~~~~

Felix is responsible for programming routes to the endpoints on its host into
the Linux kernel FIB. This ensures that packets destined for those endpoints
that arrive on at the host are forwarded accordingly.

ACL Programming
~~~~~~~~~~~~~~~

Felix is also responsible for programming ACLs into the Linux kernel. These
ACLs are used to ensure that only valid traffic can be send between
endpoints, and ensure that endpoints are not capable of circumventing
Calico's security measures. For more on this, see :doc:`security-model`.

State Reporting
~~~~~~~~~~~~~~~

Felix is responsible for providing data about the health of the network. In
particular, it reports errors and problems with configuring its host. This data
is written into etcd, to make it visible to other components and operators of
the network.


.. _calico-orchestrator-plugin:

Orchestrator Plugin
-------------------

Unlike Felix there is no single 'orchestrator plugin': instead, there are
separate plugins for each major cloud orchestration platform (e.g. OpenStack,
Kubernetes). The purpose of these plugins is to bind Calico more tightly into
the orchestrator, allowing users to manage the Calico network just as they'd
manage network tools that were built in to the orchestrator.

A good example of an orchestrator plugin is the Calico Neutron ML2 mechanism
driver. This component integrates with Neutron's ML2 plugin, and allows users
to configure the Calico network by making Neutron API calls. This provides
seamless integration with Neutron, and lowers the barrier of entry to using
Calico.

The orchestrator plugin is repsonsible for the following tasks:

API Translation
~~~~~~~~~~~~~~~

The orchestrator will inevitably have its own set of APIs for managing
networks. The orchestrator plugin's primary job is to translate those APIs into
the Calico etcd data model (see :doc:`etcd-data-model`) to allow Calico to
perform the appropriate network programming.

Some of this translation will be very simple, other bits may be more complex in
order to render a single complex operation (e.g. live migration) into the
series of simpler operations the rest of the Calico network expects.

Feedback
~~~~~~~~

If necessary, the orchestrator plugin will provide feedback from the Calico
network into the orchestrator. Examples include: providing information about
Felix liveness; marking certain endpoints as failed if network setup failed;
and so on.


.. _calico-etcd-component:

etcd
----

Calico uses etcd as its backing data store. etcd is a distributed key-value
store that has a focus on consistency, ensuring that Calico can always build an
accurate network.

In addition to its role as Calico's primary data store, etcd also acts as a
communication mechanism between the various components. We do this by having
the non-etcd components watch certain points in the keyspace to ensure that
they see any changes that have been made, allowing them to respond to those
changes in a timely manner.

The etcd component is distributed across the entire deployment. It is divided
into two groups of machines: the core cluster, and the proxies.

In Calico, we deploy an etcd cluster. In small deployments this can be an etcd
cluster of one, which provides no redundancy but is simple and low-overhead.
In larger deployments we scale this up, as per the `etcd admin guide`_.

Additionally, on each machine that hosts either a
:ref:`calico-felix-component` or a :ref:`calico-orchestrator-plugin`, we run
an etcd proxy. This is an attempt to reduce load on the core cluster and to
ensure that nodes are shielded from the specifics of the etcd cluster.

etcd is responsible for performing all of the following tasks:

.. _etcd admin guide: https://github.com/coreos/etcd/blob/master/Documentation/admin_guide.md#optimal-cluster-size

Data Storage
~~~~~~~~~~~~

etcd stores the data for the Calico network in a distributed, consistent,
fault-tolerant manner. This set of properties ensures that the Calico network
is always in a known-good state, while allowing for some number of the machines
hosting etcd to fail or become unreachable.

This distributed storage of Calico data also improves the ability of the Calico
components to read from the database (which is their most common operation), as
they can distribute their reads around the cluster.

Communication
~~~~~~~~~~~~~

etcd is also used as a communication bus between components through the
mechanism of having various components watch keys for changes. This allows the
act of committing state to the database to cause that state to be programmed
into the network.


.. _calico-bgp-component:

BGP Client (BIRD)
-----------------

Calico deploys a BGP client on every node that also hosts a
:ref:`calico-felix-component`. The role of the BGP client is read routing state
that :ref:`calico-felix-component` programs into the kernel and distribute it
around the data center.

In Calico, this BGP component is most commonly `BIRD`_, though any BGP client
that can draw routes from the kernel and distribute them is suitable in this
role.

The BGP client is responsible for performing the following tasks:

.. _BIRD: http://bird.network.cz/

Route Distribution
~~~~~~~~~~~~~~~~~~

When :ref:`calico-felix-component` inserts routes into the Linux kernel FIB,
the BGP client will pick them up and distribute them to the other nodes in the
deployment. This ensures that traffic is efficiently routed around the
deployment.


.. _calico-bgp-rr-component:

BGP Route Reflector (BIRD)
--------------------------

For larger deployments, simple BGP can become a limiting factor because it
requires every BGP client to be connected to every other BGP client in a mesh
topology. This requires an ever increasing number of connections that rapidly
become tricky to maintain.

For that reason, in larger deployments Calico will deploy a BGP route
reflector. This component, commonly used in the Internet, acts as a central
point to which the BGP clients connect, preventing them from needing to talk to
every single BGP client in the cluster.

For redundancy, multiple BGP route reflectors can be deployed seamlessly.

In calico, this BGP component is also most commonly `BIRD`_, configured as a
route reflector rather than as a standard BGP client.

The BGP route reflector is responsible for the following tasks:

Centralised Route Distribution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When :ref:`calico-bgp-component` advertises routes from its FIB to the route
reflector, the route reflector advertises those routes out to the other nodes
in the deployment.
