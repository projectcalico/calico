---
title: Details of VPP implementation & known-issues
description: Behavioral discrepencies when running with the Calico/VPP dataplane
canonical_url: '/getting-started/kubernetes/vpp/specifics'
---

Enabling VPP as the calico Dataplane should be transparent for most applications, but some specific behaviours might differ. This page gives a summary of the main differences, as well as the features that are still unsupported or with known issues.

### Behavioural differences from other dataplanes

The main difference between VPP and a regular iptables/IPVS dataplane is in the NodePorts implementation. As the constraints differ, it allows VPP to optimise the service implementation, but as a consequence, some behaviours might differ. This will mostly impact policies expecting packets to have been source NATed or not.

* For ``ClusterIPs``, ``ExternalIPs`` and ``LoadBalancerIPs`` load-balancing is done with the Maglev algorithm, and the packets are only NAT-ed on the node where the selected backend lives. This allows us to avoid source NAT-ing packets, and thus present the real client address to the destination pod. The same is true when a pod connects to a ClusterIP. This behavior allows the service load balancing to use direct service return (DSR) by default.

* For ``NodePorts`` packets are always NATed on the node targeted by the traffic. This is not the case for the eBPF dataplane where all nodes will NAT traffic to a node port regardless of the destination IP. Traffic is also always source-NATed in order for the return traffic to come back through the same node.

### Known issues & unsupported features

Although we aim at being feature complete, as VPP is still in beta status, some features are still unsupported or have known issues :

* For host endpoints policies, setting ``doNotTrack`` or ``preDNAT`` is not supported.
  * Setting them to ``true`` will result in the policy being ignored, and an error message to be printed by the calico-vpp-agent 
* VPP does not support running with ``BGP disabled``.
* ``Session affinity for services`` is not supported
* ``Wireguard`` is supported when activated cluster wide at startup time. Enabling/disabling Wireguard on a running cluster with live pods is known to be unstable.
* ``EndpointSlices`` are not supported
