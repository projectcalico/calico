---
title: Calico for CNI
---

Calico provides a CNI plugin for integration with orchestrators which use the [app/cni][appc-repo] interface.

### Supported Orchestrators
We've confirmed that the Calico CNI plugin is compatible with the following orchestrators that use CNI:

- Kubernetes - [documentation](/docs/getting-started/kubernetes/index)
- rkt - [documentation](/docs/getting-started/rkt/index)

### Supported IPAM plugins
We've confirmed that the Calico CNI plugin is compatible with the following IPAM plugins:

- `calico-ipam`: [repo](https://github.com/projectcalico/calico-cni)

The Calico CNI plugin should be compatible with any CNI IPAM plugin which returns an IPv4 and IPv6 address.  If you've used the Calico CNI plugin with another IPAM plugin, please do let us know so we can update this list.

[appc-repo]: https://github.com/appc/cni
