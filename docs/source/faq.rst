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

"How Does Calico Maintain Saved State?"
---------------------------------------

.. note:: Following the change to use etcd instead of message queues to
          communicate between components, this document may now contain out of
          date information. We will remedy this in the near future.

State is saved in a few places in a Calico deployment, depending on
whether it's global or local state.

Local state is state that belongs on a single compute host (associated
with a single running Felix instance). That state is actually entirely
stored by the Linux kernel on that host: Felix doesn't store any of it
internally. This makes Felix basically stateless, with the kernel acting
as a backing data store on one side and the plugin/ACL manger as a data
source on the other.

If Felix dies and returns, it learns current state from the kernel
(things like kernel routes, tap devices etc.) at start up. It then asks
the plugin for a full report of the state it should have, and updates
the kernel to match. This approach has strong resiliency benefits, in
that if Felix crashes you don't suddenly lose access to your VMs. As
long as the Linux kernel is running, you've still got functionality.

The bulk of global state is mastered in whatever component hosts the
plugin. In the case of OpenStack, this means a Neutron database. Our
OpenStack plugin (more strictly a Neutron ML2 driver) queries the
Neutron database to find out state about the entire deployment. That
state is then reflected down to Felix and the ACL manager. In other
orchestration systems, it may be stored in distributed databases, either
owned directly by the plugin or by the orchestrator itself.

The only other state storage in a Calico network is in the BGP sessions,
which approximate a distributed database of routes. This isn't actually
the master state (that's stored by the orchestrator), but it's the state
that is updated by Calico in response to changes in the master state.

This makes the Calico design very simple, because we store very little
state. All of our components can be shutdown and restarted without risk,
because they resynchronize state as necessary. This makes modelling
their behaviour extremely simple, reducing the complexity of bugs.

"How Does Calico Interact with the Neutron API?"
------------------------------------------------

The :doc:`calico-neutron-api` document goes into extensive detail about how
various Neutron API calls translate into Calico actions.
