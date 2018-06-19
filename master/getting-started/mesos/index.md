---
title: Integration Guide
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/'
---

{{site.prodname}} introduces IP-per-container & fine-grained security policies to Mesos, while
maintaining speed and scalability and rendering port-forwarding obsolete.

Use the navigation bar on the left to view information on {{site.prodname}}'s Mesos
integration, or continue reading for an overview of recommended guides to get
started.

## Installation

#### [Requirements](installation/prerequisites)

Information on running etcd and configuring Docker for multi-host networking.

#### [Integration Guide](installation/integration)

This method walks through the necessary manual steps to integrate {{site.prodname}} with your own deployment scripts and tools. Follow this guide if you’re integrating {{site.prodname}} with your own configuration management tools.

#### [DC/OS Installation Guide](installation/dc-os)

This guide shows how to launch {{site.prodname}}'s Installation Framework from the DC/OS Universe.

This install can be customized to lessen service impact
and improve reliability. See additional information on
[Customizing {{site.prodname}}'s DC/OS Installation Framework](installation/dc-os/custom).

## Quickstart with "{{site.prodname}}-Ready" Clusters

#### [Vagrant/VirtualBox: CentOS](installation/vagrant-centos)

Follow this guide to launch a local 2-node Mesos cluster on CentOS VMs with everything
you need to install and use {{site.prodname}}.

## Tutorials

- [Launching Tasks](tutorials/launching-tasks)
- [Connecting to Tasks](tutorials/connecting-tasks)
- [Configuring Policy for Docker Containerizer Tasks](tutorials/policy/docker-containerizer)
- [Configuring Policy for Universal Containerizer Tasks](tutorials/policy/universal-containerizer)
