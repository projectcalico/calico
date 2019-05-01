---
title: Calico with rkt
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/rkt/index'
---

Calico supports networking and network policy in a pure rkt container environment.

Use the navigation bar on the left to view information on Calico with rkt,
or continue reading for recommended guides to get started.

## Installation Guides

#### [Manual Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/rkt/installation/manual)

This method walks through the necessary manual steps to integrate Calico in a rkt environment.  Follow
this guide if you're integrating Calico with your own rkt orchestration environment.

## Quick Start Guides

#### [Vagrant with CoreOS Container Linux ]({{site.baseurl}}/{{page.version}}/getting-started/rkt/installation/vagrant-coreos/)

This guide uses Vagrant and VirtualBox to locally run a rkt-Calico enabled cluster.

## Tutorials

The following tutorials walk through policy configurations for rkt with Calico.

Before following these tutorials, ensure you've used the above guides to launch
a cluster of nodes with Calico installed.

#### [Basic network isolation]({{site.baseurl}}/{{page.version}}/getting-started/rkt/tutorials/basic)

The Basic network isolation tutorial shows how to use a Calico CNI network to
secure applications within the same rkt network.

## Troubleshooting

For rkt-specific troubleshooting information, view the
[rkt troubleshooting guide]({{site.baseurl}}/{{page.version}}/getting-started/rkt/troubleshooting).
