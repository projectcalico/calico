---
title: System requirements
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/requirements'
---

{% include {{page.version}}/reqs-sys.md orch="Kubernetes" %}

## Kubernetes requirements

#### Supported versions

We test {{site.prodname}} {{page.version}} against the following Kubernetes versions.
- 1.8
- 1.9
- 1.10

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
- `ipvs` (beta) Requires Kubernetes >=v1.9.3. Refer to
  [Enabling IPVS in Kubernetes](../../usage/enabling-ipvs) for more details.

#### IP pool configuration

The IP range selected for pod IP addresses cannot overlap with any other
IP ranges in your network, including:

- The Kubernetes service cluster IP range
- The range from which host IPs are allocated

Our manifests default to `192.168.0.0/16` for the pod IP range except [Canal/flannel](./installation/flannel),
which defaults to `10.244.0.0/16`. Refer to [Configuring the pod IP range](./installation/config-options#configuring-the-pod-ip-range)
for information on modifying the defaults.

{% include {{page.version}}/reqs-kernel.md %}