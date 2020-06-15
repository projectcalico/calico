---
title: Calico the hard way
description: A tutorial for installing Calico the hard way. 
canonical_url: '/getting-started/kubernetes/hardway/index'
---

This tutorial walks you through setting up {{site.prodname}} the hard way.

 - If you are looking to get up and running quickly with {{site.prodname}}, to try things out, check out our [quickstart guide]({{site.baseurl}}/getting-started/kubernetes/quickstart).
 - If you are looking for the most direct path to a production-ready {{site.prodname}} install, check out our [install guides]({{site.baseurl}}/getting-started/kubernetes/self-managed-onprem/onpremises).

{{site.prodname}} the hard way is optimized for learning about how {{site.prodname}} works and what the other guides do “under the hood.”

The name “{{site.prodname}} the hard way” is inspired by {% include open-new-window.html text='Kubernetes the hard way' url='https://github.com/kelseyhightower/kubernetes-the-hard-way' %} by Kelsey Hightower.

## Target Audience

This guide is for someone

 - evaluating Kubernetes networking & security options looking to deep dive, or
 - planning to build and support a {{site.prodname}} cluster in production, wanting to understand how it works

This guide assumes proficiency with either AWS web console or CLI for provisioning and accessing nodes.

## Cluster Details
{{site.prodname}} runs in many environments and supports many cluster types. To keep things reasonably prescriptive this guide focuses on Kubernetes running on AWS, but the lessons you learn apply to wherever you choose to run {{site.prodname}}. See Getting Started for a full list of cluster types (OpenShift, OpenStack, etc.).

The guide will help you install a cluster with the following {{site.prodname}} options

 - Kubernetes as the datastore
 - {{site.prodname}} CNI plugin, with BGP networking
 - {{site.prodname}} IP address management (IPAM)
 - No overlays
 - IPv4 addresses
 - Highly available Typha with mutually authenticated TLS

## Labs

 1. [Standing up Kubernetes](./standing-up-kubernetes)
 1. [The Calico datastore](./the-calico-datastore)
 1. [Configure IP pools](./configure-ip-pools)
 1. [Install CNI plugin](./install-cni-plugin)
 1. [Install Typha](./install-typha)
 1. [Install calico/node](./install-node)
 1. [Configure BGP peering](./configure-bgp-peering)
 1. [Test networking](./test-networking)
 1. [Test network policy](./test-network-policy)
 1. [End user RBAC](./end-user-rbac)
 1. [Istio integration](./istio-integration)
