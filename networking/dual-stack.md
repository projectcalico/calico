---
title: Enable dual stack
canonical_url: '/networking/dual-stack'
---

### Big picture

Arrange for each Kubernetes pod to get both IPv4 and IPv6 addresses, so that it can communicate over
both IPv4 and IPv6.

### Value

Communication over IPv6 is increasingly desirable, and the natural approach for cluster pods is to
be IPv6-native themselves, while still supporting IPv4.  Native support for both IPv4 and IPv6
is known as "dual stack", and Kubernetes has alpha-level support for this in versions 1.16 and 1.17.

### Features

This how-to guide uses the following {{site.prodname}} features:

- [**CNI plugin configuration**]({{ site.baseurl }}/reference/cni-plugin/configuration#ipam) with `assign_ipv6: true`

### Before you begin...

1.  Set up a cluster following the Kubernetes
[prerequisites](https://kubernetes.io/docs/concepts/services-networking/dual-stack/#prerequisites)
and [enablement
steps](https://kubernetes.io/docs/concepts/services-networking/dual-stack/#enable-ipv4-ipv6-dual-stack)
for dual stack, except ignore mention of the Kubenet network plugin, because here we will use
{{site.prodname}} instead.

1.  Follow our [installation
guide]({{ site.baseurl }}/getting-started/kubernetes/installation/calico) to identify
and download the right {{site.prodname}} manifest for the cluster, and
for your preferred datastore type, but do not apply that manifest yet.

### How to

To enable dual stack IP address allocation, edit the manifest as follows:

1. Edit the CNI config, which is part of the `calico-config` ConfigMap in the manifest, so that the
   `"ipam"` section reads:

   ```
       "ipam": {
           "type": "calico-ipam",
           "assign_ipv4": "true",
           "assign_ipv6": "true"
       },
   ```

1. Add the following variable settings to the environment for the calico-node container:

   | Variable name | Value |
   | ------------- | ----- |
   | `IP6`         | `autodetect` |
   | `CALICO_IPV6POOL_CIDR` | the same as the IPv6 range you configured as the cluster CIDR to kube-controller-manager and kube-proxy |
   | `FELIX_IPV6SUPPORT` | `true` |

Now apply the edited manifest with `kubectl apply -f`.

You should then observe that new pods get IPv6 addresses as well as IPv4, and can communicate with
each other and the outside world over IPv6.
