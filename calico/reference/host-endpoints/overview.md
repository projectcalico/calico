---
title: Host endpoints
description: Secure host network interfaces. 
canonical_url: '/reference/host-endpoints/index'
---

This guide describes how to use {{site.prodname}} to secure the network interfaces
of the host itself (as opposed to those of any container/VM workloads
that are present on the host). We call such interfaces "host endpoints",
to distinguish them from "workload endpoints" (such as containers or VMs).

{{site.prodname}} supports the same rich security policy model for host endpoints (host
endpoint policy) that it supports for workload endpoints. Host endpoints can
have labels, and their labels are in the same "namespace" as those of workload
endpoints. This allows security rules for either type of endpoint to refer to
the other type (or a mix of the two) using labels and selectors.

{{site.prodname}} does not support setting IPs or policing MAC addresses for host
interfaces, it assumes that the interfaces are configured by the
underlying network fabric.

{{site.prodname}} distinguishes workload endpoints from host endpoints by a configurable
prefix.  Unless you happen to have host interfaces whose name matches the
default for that prefix (`cali`), you won't need to change it.  In case you do,
see the `InterfacePrefix` configuration value at [Configuring
Felix]({{ site.baseurl }}/reference/felix/configuration).
Interfaces that start with a value listed in `InterfacePrefix` are assumed to
be workload interfaces.  Others are treated as host interfaces.

{{site.prodname}} blocks all traffic to/from workload interfaces by default;
allowing traffic only if the interface is known and policy is in place.
However, for host endpoints, {{site.prodname}} is more lenient; it only polices
traffic to/from interfaces that it's been explicitly told about. Traffic
to/from other interfaces is left alone.

You can use host endpoint policy to secure a NAT gateway or router. {{site.prodname}}
supports selector-based policy when running on a gateway or router, allowing for
rich, dynamic security policy based on the labels attached to your host endpoints.

You can apply host endpoint policies to three types of traffic:
- Traffic that is terminated locally.
- Traffic that is forwarded between host endpoints.
- Traffic that is forwarded between a host endpoint and a workload endpoint on the
same host.

Set the `applyOnForward` flag to `true` to apply a policy to forwarded traffic.
See [GlobalNetworkPolicy spec]({{ site.baseurl }}/reference/resources/globalnetworkpolicy#spec).

> **Note**: Both traffic forwarded between host endpoints and traffic forwarded
> between a host endpoint and a workload endpoint on the same host is regarded as
> `forwarded traffic`.
>
> ![]({{site.baseurl}}/images/bare-metal-packet-flows.svg)
{: .alert .alert-info}
