---
title: Pre-DNAT policy
description: Apply rules in a host endpoint policy before any DNAT.
canonical_url: '/reference/host-endpoints/pre-dnat'
---

Policy for host endpoints can be marked as `preDNAT`.  This means that rules in
that policy should be applied before any DNAT (Destination Network Address
Translation), which is useful if it is more convenient to specify {{site.prodname}} policy
in terms of a packet's original destination IP address and port, than in terms
of that packet's destination IP address and port after it has been DNAT'd.

An example is securing access to Kubernetes NodePorts from outside the cluster.
Traffic from outside is addressed to any node's IP address, on a known
NodePort, and Kubernetes (kube-proxy) then DNATs that to the IP address of one
of the pods that provides the corresponding service, and the relevant port
number on that pod (which is usually different from the NodePort).

As NodePorts are the externally advertised way of connecting to services (and a
NodePort uniquely identifies a service, whereas an internal port number may
not), it makes sense to express {{site.prodname}} policy to expose or secure particular
Services in terms of the corresponding NodePorts.  But that is only possible if
the {{site.prodname}} policy is applied before DNAT changes the NodePort to something
else. Hence this kind of policy needs `preDNAT` set to `true`.

In addition to being applied before any DNAT, the enforcement of pre-DNAT
policy differs from that of normal host endpoint policy in three key details,
reflecting that it is designed for the policing of incoming traffic from
outside the cluster:

-  Pre-DNAT policy may only have ingress rules, not egress.  (When incoming
   traffic is allowed by the ingress rules, standard connection tracking is
   sufficient to allow the return path traffic.)

-  Pre-DNAT policy is enforced for all traffic arriving through a host
   endpoint, regardless of where that traffic is going, and - in particular -
   even if that traffic is routed to a local workload on the same host.
   (Whereas normal host endpoint policy is skipped, for traffic going to a
   local workload.)

-  There is no 'default drop' semantic for pre-DNAT policy (as there is for
   normal host endpoint policy).  In other words, if a host endpoint is defined
   but has no pre-DNAT policies that explicitly allow or deny a particular
   incoming packet, that packet is allowed to continue on its way, and will
   then be accepted or dropped according to workload policy (if it is going to
   a local workload) or to normal host endpoint policy (if not).

