---
title: Calico for Kubernetes
---

Calico enables first-class networking and network policy in Kubernetes clusters across the cloud.  Calico works
everywhere - on all major public cloud providers and private clouds as well.

Calico supports the Kubernetes [NetworkPolicy API](http://kubernetes.io/docs/user-guide/networkpolicies/),
and can also be used to implement even [more fine-grained policy](tutorials/advanced-policy)
using the Calico APIs directly.

Use the navigation bar on the left to view information on Calico for Kubernetes,
or continue reading for recommended guides to get started.

## Installing Calico for Kubernetes

There are two main ways to install Calico on Kubernetes.

#### [Hosted Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted)

This method uses Kubernetes manifests to install Calico for Kubernetes, using Kubernetes.
Calico manifests ensure the necessary components are installed and run on each node in the cluster.

#### [Integration Guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/integration)

This method walks through the necessary manual steps to integrate Calico with your own deployment scripts and tools.  Follow
this guide if you're integrating Calico with your own configuration management tools.

## Guides

The following guides walk through launching a CoreOS based Kubernetes cluster on various providers, using a
Calico self-hosted installation.

#### [AWS]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/aws)

This guide covers launching a Kubernetes cluster on AWS with Calico.

#### [GCE]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/gce)

This guide covers launching a Kubernetes cluster on GCE with Calico.

#### [Vagrant and Container Linux by CoreOS ]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/vagrant/)

This guide uses Vagrant and VirtualBox to locally run a Kubernetes
cluster with Calico.

## Using Calico with Kubernetes

The following tutorials walk through policy configurations for Calico in Kubernetes.

Before following these tutorials, ensure you've used the above guides to launch
a Kubernetes cluster with Calico installed.

#### [Simple Policy](tutorials/simple-policy)

The Simple Policy Demo shows how to use Calico to secure a simple two-tier application in kubernetes.

#### [Stars Demo](tutorials/stars-policy/)

The Stars Demo features a UI which actively shows blocked and allowed
connections as policy is implemented.

#### [Advanced Policy Demo](tutorials/advanced-policy)

The advanced policy demo walks through using Calico to provide policy features beyond
what can be done with the Kubernetes NetworkPolicy API like egress and CIDR based policy.

## Third Party Integrations

A number of popular Kubernetes installers use Calico to provide networking and/or network policy.
Here are a few, listed alphabetically.

- [Apprenda Kismatic Enterprise Toolkit](https://github.com/apprenda/kismatic)
- [Container Linux by CoreOS](https://coreos.com/kubernetes/docs/latest/)
- [GCE](http://kubernetes.io/docs/getting-started-guides/network-policy/calico/)
- [Kargo](https://github.com/kubernetes-incubator/kargo)
- [Kops](https://github.com/kubernetes/kops)
- [StackPointCloud](https://stackpoint.io)
- [Gravitational Telekube](http://gravitational.com/blog/gravitational-tigera-partnership/)

## Troubleshooting

For Kubernetes-specific troubleshooting information, view the [k8s troubleshooting guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/troubleshooting) guide.
