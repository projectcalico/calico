---
title: Calico for CNI
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v1.6/reference/advanced/calico-cni'
---
Calico provides a CNI plugin for integration with orchestrators which use the [containernetworking/cni][containernetworking-repo] interface.

### Supported Orchestrators
We've confirmed that the Calico CNI plugin is compatible with the following orchestrators that use CNI:

- Kubernetes - [documentation]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/)
- rkt - [documentation]({{site.baseurl}}/{{page.version}}/getting-started/rkt/)

### Supported IPAM plugins
We've confirmed that the Calico CNI plugin is compatible with the following IPAM plugins:
- `calico-ipam`: [repo](https://github.com/projectcalico/calico-cni)
- `host-local`: [repo](https://github.com/containernetworking/cni/blob/master/Documentation/host-local.md)

The Calico CNI plugin should be compatible with any CNI IPAM plugin which returns an IPv4 and IPv6 address.  If you've used the Calico CNI plugin with another IPAM plugin, please do let us know so we can update this list.

[containernetworking-repo]: https://github.com/containernetworking/cni
