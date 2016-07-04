.. # Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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

What is Calico?
===============

Calico is a new approach to virtual networking, based on the same scalable IP
networking principles as the Internet.  It targets data centers where most of
the workloads (VMs, containers or bare metal servers) only require IP
connectivity, and provides that using standard IP routing.  Isolation between
workloads - whether according to tenant ownership, or any finer grained
policy - is achieved by iptables programming at the servers hosting the source
and destination workloads.

In comparison with the common solutions that provide simulated layer 2
networks, Calico is a lot simpler, specifically in the following ways.

- Packets flowing through a Calico network do not require additional
  encapsulation and decapsulation anywhere.  In contrast, layer 2 solutions
  typically require packets to be encapsulated in a tunneling protocol when
  travelling between host servers.

- Where permitted by policy, Calico packets can be routed between different
  tenants' workloads, or out to or in from the Internet, in exactly the same
  way as between the workloads of a single tenant.  There is no need for on-
  and off-ramps as in overlay solutions, and hence for passing through special
  'networking' or 'router' nodes that provide those ramps.

- As a consequence of those two points, Calico networks are easier to
  understand and to troubleshoot.  Standard tools like ping and traceroute work
  for probing connectivity, and tcpdump and Wireshark for looking at flows -
  because Calico packets are just IP packets, and the same throughout the
  network.

- Security policy is specified (using ACLs) and implemented (iptables) in a
  single uniform way - making it more likely that it will actually be correct
  and robust.  In contrast, in layer 2 solutions, effective security policy is
  a more complex (but also less expressive) product of the networks and
  security groups that are defined for each tenant, and of any virtual
  'routers' that have been defined to allow passage between tenant networks.

For more detail please check out the following pages.

.. toctree::
   :maxdepth: 2

   datapath
   addressing
   security-model
