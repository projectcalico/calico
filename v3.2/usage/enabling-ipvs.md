---
title: Enabling IPVS in Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.1/usage/enabling-ipvs'
---

{{site.prodname}} has beta-level support for `kube-proxy`'s `ipvs` proxy mode.
{{site.prodname}} `ipvs` support is activated automatically if {{site.prodname}}
detects that `kube-proxy` is running in that mode.

`ipvs` mode promises greater scale and performance vs `iptables` mode.
However, it comes with some limitations.  In IPVS mode:

- `kube-proxy` has a [known issue](https://github.com/kubernetes/kubernetes/issues/58202)
  affecting hosts with host interfaces that that are **not** named using the
  pattern `ethN`.
- {{site.prodname}} requires [additional `iptables` packet mark bits](../reference/felix/configuration#ipvs-bits)
  in order to track packets as they pass through IPVS.
- {{site.prodname}} needs to be [configured](../reference/felix/configuration#ipvs-portranges)
  with the port range that is assigned to Kubernetes NodePorts.  If services
  do use NodePorts outside {{site.prodname}}'s expected range,
  {{site.prodname}} will treat traffic to those ports as host traffic instead
  of pod traffic.
- {{site.prodname}} does not yet support Kubernetes services that make use of a
  locally-assigned ExternalIP.  {{site.prodname}} does support ExternalIPs that
  are implemented via an external load balancer.
- {{site.prodname}} has not yet been scale tested with `ipvs`.

 {{site.prodname}} will detect if you change `kube-proxy`'s proxy mode after 
 {{site.prodname}} has been deployed. Any Kubernetes `ipvs`-specific configuration 
 needs to be [configured](../reference/felix/configuration#ipvs-portranges) 
 before changing the `kube-proxy` proxy mode to `ipvs`.