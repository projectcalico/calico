---
title: Calico with Docker
---

Calico drives container connectivity and implements network policy for Docker containers.

Use the navigation bar on the left to view information on Calico for Docker,
or continue reading for recommended guides to get started.

## [Prerequisites]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/manual)

This guide explains host requirements for Calico to function properly as a
Docker networking plugin.


## [Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/basic)

This guide details how to add manually add Calico to Docker.

## Quickstart with "Calico-Ready" Clusters

Calico maintains sample cloud-config files which can be used to launch a Docker
cluster ready for Calico to be installed on.

The following guides walk through launching a CoreOS cluster using these cloud-config scripts on various cloud providers and locally.
These Docker clusters will not install Calico for users, leaving you to
follow the above installation method to run Calico.

#### [Vagrant CoreOS]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/vagrant/)

This guide uses Vagrant with VirtualBox to launch a Calico-ready cluster.

#### [AWS Tutorial]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/aws)

AWS cluster configurations tend to vary greatly based off the needs of the user.
Calico's Manual Install Guide (above) serves as a general guide still applicable
to any AWS cluster. We strongly recommend AWS deployers read the
[General Calico AWS Reference]({{site.baseurl}}/{{page.version}}/reference/public-cloud/aws)
for information on how to properly configure their hosts before getting started.

#### [GCE]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/gce)

This guide covers launching a cluster on GCE for use with Calico.

#### [Digital Ocean]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/digital-ocean)

This guide covers launching a cluster on Digital Ocean for use with Calico.

## Usage Tutorials

With a ready Docker Cluster and Calico Installed, use the following guides
to see how to configure policy for your Kubernetes pods.

#### [Advanced Policy](tutorials/simple-policy)

The Advanced Policy Demo shows how secure a simple frontend-database application
pod using Calico Policy

#### [Stars Demo](tutorials/stars-policy/)

The Stars Demo features a sleek UI which shows in real-time blocked and allowed
connections as policy is implemented.

## Troubleshooting

For Kubernetes-specific troubleshooting information, view the [K8s Troubleshooting Guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/troubleshooting) guide.

For general Calico troubleshooting, see [Calico Troubleshooting](troubleshooting.md)
