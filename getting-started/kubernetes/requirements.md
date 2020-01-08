---
title: System requirements
canonical_url: '/getting-started/kubernetes/requirements'
---

{% include content/reqs-sys.md orch="Kubernetes" %}

## Kubernetes requirements

#### Supported versions

We test {{site.prodname}} {{page.version}} against the following Kubernetes versions.

- 1.14
- 1.15
- 1.16

Other versions are likely to work, but we do not actively test {{site.prodname}}
{{page.version}} against them.

#### CNI plug-in enabled

{{site.prodname}} is installed as a CNI plugin. The kubelet must be configured
to use CNI networking by passing the `--network-plugin=cni` argument. (On
kubeadm, this is the default.)

#### Other network providers

{{site.prodname}} must be the only network provider in each cluster. We do
not currently support migrating a cluster with another network provider to
use {{site.prodname}} networking.

#### Supported kube-proxy modes

{{site.prodname}} supports the following kube-proxy modes:
- `iptables` (default)
- `ipvs` Requires Kubernetes >=v1.9.3. Refer to
  [Enabling IPVS in Kubernetes](../../networking/enabling-ipvs) for more details.

#### IP pool configuration

The IP range selected for pod IP addresses cannot overlap with any other
IP ranges in your network, including:

- The Kubernetes service cluster IP range
- The range from which host IPs are allocated

## Application layer policy requirements

- [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook) enabled
- Istio [v1.0](https://istio.io/about/notes/1.0/), [v1.1](https://archive.istio.io/v1.1/), [v1.2](https://archive.istio.io/v1.2/), or [v1.3](https://archive.istio.io/v1.3/)

Note that Kubernetes version 1.16+ requires Istio version 1.2 or greater.

{% include content/reqs-kernel.md %}
