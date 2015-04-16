.. # Copyright (c) Metaswitch Networks 2015. All rights reserved.
   #
   #    Licensed under the Apache License, Version 2.0 (the "License"); you may
   #    not use this file except in compliance with the License. You may obtain
   #    a copy of the License at
   #
   #         http://www.apache.org/licenses/LICENSE-2.0
   #
   #    Unless required by applicable law or agreed to in writing, software
   #    distributed under the License is distributed on an "AS IS" BASIS,
   #    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   #    implied. See the License for the specific language governing
   #    permissions and limitations under the License.

Calico Component Architecture
=============================

Felix and the Calico Plugin
---------------------------

This document describes the architecture of Calico, where Calico's core
function is separated from the integration of that function
into the environment that Calico is running – for example, OpenStack,
Docker, CoreOS or some other cloud OS.

The components of this architecture, and the interactions between them,
are shown in the following diagram.

.. figure:: _static/calico_API_arch_Sept_2014.png
   :alt:

Each segment is broken down below.

Felix
^^^^^

Felix (a.k.a. The Calico Agent) is the daemon responsible for
programming the Linux host machines. This daemon has a number of
responsibilities. It is responsible for programming ACLs and routes into
the Linux kernel. It may also be required to perform VM discovery (if it
is not expecting to be notified of VM creation). It exchanges
information with the Cloud Orchestration Provider via the Calico
Plug-In. The information it exchanges
northwards is defined by the Calico API, which is conceptually split
into several parts (see below). Felix is in effect the portion of Calico
that does the actual heavy lifting, turning an abstract networking model
into configuration on compute hosts that creates the real network
topology.

On some platforms, Felix may be responsible for doing groundwork for
other processes. For example, in OpenStack Felix is responsible for
programming NAT rules for use by the OpenStack Metadata Agent.

Felix is responsible for ensuring that the centrally-determined routing
policy is put in place on all machines that require it, and that the
system is stable and secure. It is not expected that instances of Felix
will communicate amongst themselves in a peer-to-peer fashion: such
logic should not be required.

Cloud Orchestration Provider
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The cloud orchestration provider represents the logic of whatever cloud
system Calico is running in. This function is responsible for arranging
compute resource and for managing lots of knowledge in a
platform-specific manner. The expectation is that Project Calico will
need to make few or no changes to the upstream orchestration provider.

Calico Plug-In
~~~~~~~~~~~~~~

The Calico Plug-in is the component responsible for providing
translation between the Cloud Orchestration Provider and the Calico
Endpoint and Network APIs. This layer will also handle all communication
between Felix and the orchestration provider.

The Calico Plug-In is responsible for providing all information required
by the Calico Endpoint API. This can actually happen in a bi-directional
manner. Depending on the situation, Felix may request information from
the Calico Plug-In about endpoints on its own (e.g. by discovering tap
interfaces, as in the OpenStack case) or it may be instructed to take
ownership of interfaces by the Calico Plug-In. Exactly which flow is
used depends on the Cloud Orchestration Provider being used.

Calico API
^^^^^^^^^^

The Calico API is conceptually divided into three parts:

-  The Calico Endpoint API - this communicates data *about* endpoints
   (such as IP addresses, MAC address, and so on)

More detail on the API is provided in :doc:`api-proposal`.

BGP Stack (not present on diagram)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The BGP stack is not present on the diagram, but is nevertheless part of
the overall Calico architecture.

Felix does not talk to the BGP stack directly, but instead the BGP stack
is programmed via the Linux kernel. In effect, the programming of the
BGP stack happens as a result of Felix adding static routes to the
kernel, not in response to any 'BGP programming' action taken by Felix.
This means that there is effectively no direct interface between the BGP
stack and any other part of Calico.

Example Flow
------------

The following is an example flow of information through this
architecture. This is an example of Endpoint provisioning in an IPv4
network.

1. Felix spots the creation of a likely endpoint interface, for example
   by noticing the appearance of a new TAP interface (Endpoint
   discovery). It makes a request over the Calico Endpoint API to the
   Calico Plug-In asking for data about the Endpoint to which the
   interface belongs.
2. The Calico Plug-In receives the request. It uses whatever plug-in
   interface is defined by the Cloud Orchestration Provider to determine
   information about that Endpoint. In this instance the most important
   information is the IP address of the machine behind the interface and
   some unique identifier for the Endpoint.
3. Felix receives the response over the Calico Endpoint API including any ACL
   rules. It programs the static route for that Endpoint into the FIB. It also
   enables proxy ARP on the Endpoint interface and sets up any necessary NAT
   rules for metadata acquisition.
4. Felix programs those ACL rules into the kernel.
5. Felix signals to the Calico Plug-In that the Endpoint is successfully
   provisioned (if necessary).
