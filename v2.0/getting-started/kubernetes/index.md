---
title: Calico for Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/kubernetes/'
---

Calico enables networking and network policy in Kubernetes clusters across the cloud.  Calico works
everywhere - on all major public cloud providers and private cloud as well.

Calico uses a pure IP networking fabric to provide high performance networking, and its battle-tested policy engine
enforces high-level, intent-focused network policy.  Together, Calico and Kubernetes provide a secure,
cloud-native platform that can scale your infrastructure to hundreds of thousands of workloads.

## Installing Calico for Kubernetes

There are a number of ways to install Calico and Kubernetes.  The [installation documentation](installation)
includes links to a number of popular guides and installers which use Calico. It also
includes information on installing Calico on a from-scratch Kubernetes cluster using either a self-hosted Kubernetes manifest,
or by integrating Calico into your own configuration management scripts.

## Using Calico with Kubernetes

Once you have a Kubernetes cluster with Calico installed, the following articles will help you
get familiar with Calico and make the most of the features that Calico provides.

##### Tutorials

**[Using the NetworkPolicy API](tutorials/simple-policy)**: this guide explains how to use Calico to secure a simple two-tier application
using the Kubernetes NetworkPolicy API.

**[Advanced Calico Policy](tutorials/advanced-policy)**: this guide explains how to use Calico to provide policy features beyond
what can be done with the Kubernetes NetworkPolicy API like egress and CIDR based policy.

**[Stars Demo](tutorials/stars-policy/)**: this demo features a UI which actively shows blocked and allowed connections as policy is implemented.

##### Usage Reference

**[Using the calicoctl CLI tool][calicoctl]**: reference documentation for the Calico CLI tool, calicoctl.

**[Configuring BGP Peering][bgp-peering]**: this guide is for users on private cloud who want to configure Calico to peer with their underlying infrastructure.

[calicoctl]: {{site.baseurl}}/{{page.version}}/reference/calicoctl/
[bgp-peering]: {{site.baseurl}}/{{page.version}}/usage/configuration/bgp
