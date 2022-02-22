---
title: System requirements
description: Review requirements before installing Calico to ensure success.
canonical_url: '/getting-started/kubernetes/requirements'
---

{% include content/reqs-sys.md orch="Kubernetes" %}

## Kubernetes requirements

#### Supported versions

We test {{site.prodname}} {{page.version}} against the following Kubernetes versions.

- v1.21
- v1.22
- v1.23

Due to changes in the Kubernetes API, {{site.prodname}} {{page.version}} will not work
on Kubernetes v1.15 or below.  v1.16-v1.18 may work, but they are no longer tested. 
Newer versions may also work, but we recommend upgrading to a version of {{site.prodname}}
that is tested against the newer Kubernetes version.

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

- {% include open-new-window.html text='MutatingAdmissionWebhook' url='https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook' %} enabled
- Istio {% include open-new-window.html text='v1.9' url='https://istio.io/about/notes/1.9/' %} or {% include open-new-window.html text='v1.10' url='https://archive.istio.io/v1.10/' %}

Note that Kubernetes version 1.16+ requires Istio version 1.2 or greater.
Note that Istio version 1.9 requires Kubernetes version 1.17-1.20.
Note that Istio version 1.10 is supported on Kubernetes version 1.18-1.21, but has been tested on Kubernetes version 1.22.

As of Kubernetes v1.23, FlexVolumes have been deprecated in favor of the Container Storage Interface (CSI). Since our current application layer policy integration depends on FlexVolumes, it will not work on Kubernetes v1.23+.

{% include content/reqs-kernel.md %}
