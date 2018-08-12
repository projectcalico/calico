---
title: Calico with Docker
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/'
---

Calico implements a Docker network plugin that can be used to provide routing and advanced network policy for Docker containers.

Use the navigation bar on the left to view information on Calico for Docker,
or continue reading for an overview of recommended guides to get started.


## Installation

#### [Requirements](installation/requirements)

Information on running etcd and configuring Docker for multi-host networking.

#### [Installation Guide]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/manual)

Learn the two-step process for launching Calico for Docker.

## Quickstart with "Calico-Ready" Clusters

#### [Vagrant/VirtualBox: Container Linux by CoreOS](installation/vagrant-coreos)

Follow this guide to launch a local 2-node CoreOS Container Linux cluster with everything
you need to install and use Calico.

#### [Vagrant Ubuntu](installation/vagrant-ubuntu)

Follow this guide to launch a local 2-node Ubuntu cluster with everything
you need to install and use Calico.

## Tutorials

#### [Simple Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/simple-policy)

The above guide demonstrates Calico connectivity cross host, and how to limit
that connectivity using simple Calico policy.

#### [Advanced Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/advanced-policy)

The above guide digs deeper into advanced policy configurations for workloads.

#### [IPAM]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/ipam)

This guide walks through configuring a Docker network for use with Calico and how to statically assign IP addresses from that network
