---
title: Installing Calico on Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/'
---

{{site.prodname}} can be installed on a Kubernetes cluster in a number of configurations.  This document
gives an overview of the most popular approaches, and provides links to each for more detailed
information.

## Requirements

{{site.prodname}} can run on any Kubernetes cluster which meets the following criteria.

- The kubelet must be configured to use CNI network plugins (e.g `--network-plugin=cni`).
- kube-proxy must be started in one of the following modes:

   - `iptables` the default as of Kubernetes v1.2.0
   - `ipvs` {{site.prodname}} supports this at the beta level with
     [some limitations](#kube-proxy-ipvs-mode). Requires Kubernetes v1.9.3 or later due to
     critical bugs in earlier releases.

- For kube-proxy `ipvs` mode, Kubernetes v1.9.3 or above is required due to
  critical bugs in earlier releases.
- The kube-proxy must be started without the `--masquerade-all` flag, which conflicts with {{site.prodname}} policy.
- The Kubernetes `NetworkPolicy` API requires at least Kubernetes version v1.3.0.
- When RBAC is enabled, the proper accounts, roles, and bindings must be defined
  and utilized by the {{site.prodname}} components.  Examples exist for both the [etcd](rbac.yaml) and
  [kubernetes api](hosted/rbac-kdd.yaml) datastores.

## [{{site.prodname}} Hosted Install](hosted)

Installs the {{site.prodname}} components as a DaemonSet entirely using Kubernetes manifests through a single
kubectl command.  This method is supported for Kubernetes versions >= v1.4.0.

## [Custom Installation](integration)

In addition to the hosted approach above, the {{site.prodname}} components can also be installed using your
own orchestration mechanisms (e.g ansible, chef, bash, etc)

Follow the [integration guide](integration) if you're using a Kubernetes version < v1.4.0, or if you would like
to integrate {{site.prodname}} into your own installation or deployment scripts.

## Third Party Integrations

A number of popular Kubernetes installers use {{site.prodname}} to provide networking and/or network policy.

You can find some of them here, organized by cloud provider.

- [Amazon Web Services](aws)
- [Google Compute Engine](gce)
- [Microsoft Azure](azure)

## kube-proxy IPVS mode

{{site.prodname}} has beta-level support for `kube-proxy`'s `ipvs` proxy mode.
{{site.prodname}} `ipvs` support is activated automatically if {{site.prodname}}
detects that `kube-proxy` is running in that mode.

`ipvs` mode promises greater scale and performance vs `iptables` mode.
However, it comes with some limitations.  In IPVS mode:

- `kube-proxy` has a [known issue](https://github.com/kubernetes/kubernetes/issues/58202)
  affecting hosts with host interfaces that that are **not** named using the
  pattern `ethN`.
- {{site.prodname}} requires [additional `iptables` packet mark bits](../../../reference/felix/configuration#ipvs-bits)
  in order to track packets as they pass through IPVS.
- {{site.prodname}} needs to be [configured](../../../reference/felix/configuration#ipvs-portranges)
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
 needs to be [configured](../../../reference/felix/configuration#ipvs-portranges) 
 before changing the `kube-proxy` proxy mode to `ipvs`.
