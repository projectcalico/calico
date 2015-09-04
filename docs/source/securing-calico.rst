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

Securing Calico
===============

What Calico does and does not provide
-------------------------------------

Currently, Calico implements security policy that ensures that:

- an endpoint cannot spoof its source address
- all traffic going to an endpoint must be accepted by the inbound policy
  attached to that endpoint
- all traffic leaving an endpoint must be accepted by the outbound policy
  attached to that endpoint.

However, there are several areas that Calico does not currently cover (we're
working on these and we'd love to hear from you if you're interested!).
Calico does not:

- prevent an endpoint from probing the network (if its outbound policy allows
  it); in particular, it doesn't prevent an endpoint from contacting compute
  hosts or etcd
- prevent an endpoint from flooding its host with DNS/DHCP/ICMP traffic
- prevent a compromised host from spoofing packets.

Since the outbound policy is typically controlled by the application developer
who owns the endpoint (at least when Calico is used with OpenStack), it's a
management challenge to use that to enforce *network* policy.

How Calico uses iptables
------------------------

Calico needs to add its security policy rules to the "INPUT" and "FORWARD"
chains of the iptables "filter" table.  To minimise the impact on the
top-level chains, Calico inserts a single rule at the start of each of the
kernel chains, which jumps to Calico's own chain.

The INPUT chain is traversed by packets which are destined for the host itself.
Calico's INPUT rules only apply to packets arriving from Calico-managed
endpoints; other packets are passed through to the remainder of the INPUT
chain.

In the INPUT chain, Calico whitelists some essential bootstrapping traffic,
such as DHCP, DNS and the OpenStack metadata traffic.  Other traffic from
local endpoints passes through the outbound rules for the endpoint.  Then,
it hits a configurable rule that either drops the traffic or allows it to
continue to the remainder of the INPUT chain.

Presently, the Calico FORWARD chain is not similarly configurable.  All traffic
that is heading to or from a local endpoint is processed through the relevant
security policy.  Then, if the policy accepts the traffic, it is accepted.
If the policy rejects the traffic it is immediately dropped.

To prevent IPv6-enabled endpoints from spoofing their IP addresses, Felix
inserts a reverse path filtering rule in the iptables "raw" PREROUTING chain.
(For IPv4, it enables the rp_filter sysctl on each interface that it controls.)

Securing iptables
-----------------

In a production environment, we recommend setting the default policy for the
INPUT and FORWARD chains to be DROP and then explicitly whitelisting the
traffic that should be allowed.

Securing etcd
-------------

Calico uses etcd to store and forward the configuration of the network from
plugin to the Felix agent.  By default, etcd is writable by anyone with
access to its REST interface.  We plan to use the RBAC feature of an upcoming
etcd release to improve this dramatically.  However, until that work is done,
we recommend blocking access to etcd from all but the IP range(s) used by the
compute nodes and plugin.
