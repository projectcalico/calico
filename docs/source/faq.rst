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

Frequently Asked Questions
==========================

This page contains answers to several frequently asked technical questions
about Calico. It is updated on a regular basis: please check back for more
information.

"Why use Calico?"
-----------------

The problem Calico tries to solve is the networking of workloads (VMs,
containers, etc) in a high scale environment.  Existing L2 based methods for
solving this problem have problems at high scale.  Compared to these, we think
Calico is more scalable, simpler and more flexible.  We think you should look
into it if you have more than a handful of nodes on a single site.

For a more detailed discussion of this topic, see our blog post at
`Why Calico? <http://www.projectcalico.org/why-calico/>`__.

"Does Calico work with IPv6?"
-----------------------------

Yes!  We have demonstrated IPv6 with Calico on OpenStack and Docker/Powerstrip.

"Is Calico compliant with PCI/DSS requirements?"
------------------------------------------------

PCI certification applies to the whole end-to-end system, of which Calico would
be a part.  We understand that most current solutions use VLANs, but after
studying the PCI requirements documents, we believe that Calico does meet those
requirements and that nothing in the documents *mandates* the use of VLANs.

"How does Calico maintain saved state?"
---------------------------------------
State is saved in a few places in a Calico deployment, depending on
whether it's global or local state.

Local state is state that belongs on a single compute host, associated with a
single running Felix instance (things like kernel routes, tap devices
etc.). Local state is entirely stored by the Linux kernel on the host, with
Felix storing it only as a temporary mirror. This makes Felix effectively
stateless, with the kernel acting as a backing data store on one side and
`etcd` as a data source on the other.

If Felix is restarted, it learns current local state by interrogating the
kernel at start up. It then reads from ``etcd`` all the local state which it
should have, and updates the kernel to match. This approach has strong
resiliency benefits, in that if Felix restarts you don't suddenly lose access
to your VMs or containers. As long as the Linux kernel is running, you've still
got full functionality.

The bulk of global state is mastered in whatever component hosts the
plugin.

- In the case of OpenStack, this means a Neutron database. Our OpenStack plugin
  (more strictly a Neutron ML2 driver) queries the Neutron database to find out
  state about the entire deployment. That state is then reflected to ``etcd``
  and so to Felix.

- In certain cases, ``etcd`` itself contains the master copy of the data. This
  is because some Docker deployments have an ``etcd`` cluster that has the
  required resiliency characteristics, used to store all system configuration -
  and so ``etcd`` is configured so as to be a suitable store for critical data.

- In other orchestration systems, it may be stored in distributed databases,
  either owned directly by the plugin or by the orchestrator itself.

The only other state storage in a Calico network is in the BGP sessions, which
approximate a distributed database of routes. This BGP state is simply a
replicated copy of the per-host routes configured by Felix based on the global
state provided by the orchestrator.

This makes the Calico design very simple, because we store very little
state. All of our components can be shutdown and restarted without risk,
because they resynchronize state as necessary. This makes modelling
their behaviour extremely simple, reducing the complexity of bugs.

"How does Calico interact with the Neutron API?"
------------------------------------------------

The :doc:`calico-neutron-api` document goes into extensive detail about how
various Neutron API calls translate into Calico actions.

"I've heard Calico uses Proxy ARP - surely that doesn't scale?"
---------------------------------------------------------------

On each compute host, Calico uses the proxy ARP technique to intercept *all*
ARP requests from each workload, returning the MAC address of the compute host
as the next hop.  As Calico is responding to all ARP requests from a workload,
there is no distribution of MAC addresses between compute nodes and, hence,
none of the usual proxy ARP scalability issues arise.
