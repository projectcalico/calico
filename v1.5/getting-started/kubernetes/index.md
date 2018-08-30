---
title: Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/kubernetes/'
---
Calico can be used as a network plugin for Kubernetes to provide connectivity and network policy in a Kubernetes cluster.
Calico allows you to enforce fine-grained network security policy natively in Kubernetes. The video below shows a quick demonstration of Calico policy in action.

[![IMAGE ALT TEXT](https://img.youtube.com/vi/OE1n5PWtvMM/0.jpg)](https://www.youtube.com/watch?v=OE1n5PWtvMM "Calico network policy on Kubernetes")

## Getting Started

The following guides help you get started with Calico.

Integration guide
------------------

- [Integration Guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/): Discusses adding Calico to an existing cluster, or integrating Calico with your own install scripts.

Quick-start guides
------------------
These guides let you get a cluster set up quickly, and walk you through using Calico for networking and network policy.

- [CoreOS Vagrant]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/vagrant/)
- [CoreOS on GCE]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/gce)
- [CoreOS on AWS]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/aws)

## Requirements

- The kube-proxy must be started in `iptables` proxy mode.  This is the default as of Kubernetes v1.2.0.
- The kube-proxy must be started without the `--masquerade-all` flag, which conflicts with Calico policy.

## Troubleshooting
- [Troubleshooting]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/troubleshooting)
