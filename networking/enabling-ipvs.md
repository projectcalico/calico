---
title: Enable IPVS in Kubernetes
description: Use IPVS kube-proxy for load balancing traffic across pods
canonical_url: '/networking/enabling-ipvs'
---

{{site.prodname}} has support for `kube-proxy`'s `ipvs` proxy mode.
{{site.prodname}} `ipvs` support is activated automatically if {{site.prodname}}
detects that `kube-proxy` is running in that mode.

`ipvs` mode provides greater scale and performance vs `iptables` mode.
However, it comes with some limitations.  In IPVS mode:

- {{site.prodname}} requires [additional `iptables` packet mark bits](../reference/felix/configuration#ipvs-bits)
  in order to track packets as they pass through IPVS.
- {{site.prodname}} needs to be [configured](../reference/felix/configuration#ipvs-portranges)
  with the port range that is assigned to Kubernetes NodePorts.  If services
  do use NodePorts outside {{site.prodname}}'s expected range,
  {{site.prodname}} will treat traffic to those ports as host traffic instead
  of pod traffic.

 {{site.prodname}} will detect if you change `kube-proxy`'s proxy mode after 
 {{site.prodname}} has been deployed. Any Kubernetes `ipvs`-specific configuration 
 needs to be [configured](../reference/felix/configuration#ipvs-portranges) 
 before changing the `kube-proxy` proxy mode to `ipvs`.
