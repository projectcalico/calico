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

#### [Vagrant/VirtualBox: Ubuntu](installation/vagrant-ubuntu)

Follow this guide to launch a local 2-node Ubuntu cluster with everything
you need to install and use Calico.

## Tutorials

#### [Security using Calico Profiles]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-calico-profiles)

The above guide demonstrates Calico connectivity cross host, and how to limit
that connectivity using simple Calico profiles.  One profile is created for
each network and the connectivity is defined as policy on each profile.

#### [Security using Calico Profiles and Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-calico-profiles-and-policy)

The above guide digs deeper into advanced policy configurations for workloads.
There is stil one profile created for each network but now the profiles define
labels that are inherited by each container added to the network.  The policy uses
the labels in selectors to configure connectivity.

#### [Security using Docker Labels and Calico Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-docker-labels-and-calico-policy)

The above guide demonstrates Calico connectivity between containers without using
Profiles at all.  Instead, Calico Policies are defined which apply to
containers depending on the labels assigned to them at runtime.  This allows
policy adjustment at the container level rather than at the network level.

#### [IPAM]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/ipam)

This guide walks through configuring a Docker network for use with Calico and how to statically assign IP addresses from that network
