---
title: Kubernetes
---

Calico drives pod connectivity and implements network policy for Kubernetes clusters.
Calico allows you to enforce fine-grained network security policy natively in Kubernetes. The video below shows a quick demonstration of Calico policy in action.

[![Calico for Kubernetes Demo Video](http://img.youtube.com/vi/OE1n5PWtvMM/0.jpg)](http://www.youtube.com/watch?v=OE1n5PWtvMM "Calico network policy on Kubernetes")

<!-- Turk TODO: download thumbnail and host locally to fix this pathetic excuse for a thumbnail. -->

Use the navigation bar on the left to view information on Calico for Kubernetes,
or continue reading for recommended guides to get started.

## Installation Guides

There are several ways to install Calico in Kubernetes.

#### [Hosted Install Guide (Beta)]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted)

Calico's Hosted Install uses Kubernetes Manifests to install Calico for Kubernetes, using Kubernetes.
Calico manifests ensure the necessary artifacts and configurations are added to each host, and the necessary services are started.

>Note: Hosted installs are new for Kubernetes v1.4 and Calico's Manifests are still in Beta. It will become
the supported installation method going forward.

#### [Manual Install Guide (Recommended)]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/)

This guide details how to add manually add Calico to an existing, stock Kubernetes cluster.


## Quickstart with "Calico-Ready" Clusters

Calico maintains sample cloud-config files which can be used to launch a Kubernetes
cluster ready for Calico to be installed on.

The following guides walk through launching a CoreOS cluster using these cloud-config scripts on various cloud providers and locally.
These Kubernetes clusters will not install Calico for users, leaving you to
follow either of the above installation methods to run Calico.

#### [CoreOS Vagrant]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/vagrant/)

This guide uses Vagrant with VirtualBox to launch a Calico-ready cluster.

#### [AWS Tutorial]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/aws)

AWS cluster configurations tend to vary greatly based off the needs of the user.
Calico's Manual Install Guide (above) serves as a general guide still applicable
to any AWS cluster. We strongly recommend AWS deployers read the
[General Calico AWS Reference]({{site.baseurl}}/{{page.version}}/reference/public-cloud/aws)
for information on how to properly configure their hosts before getting started.


#### [GCE]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/gce)

This guide covers launching a cluster on GCE for use with Calico.

## Usage Tutorials

With a ready Kubernetes Cluster and Calico Installed, use the following guides
to see how to configure policy for your Kubernetes pods.

#### [Simple Policy](tutorials/simple-policy)

The Simple Policy Demo shows how secure a simple frontend-database application
pod using Calico Policy

#### [Stars Demo](tutorials/stars-policy/)

The Stars Demo features a sleek UI which shows in real-time blocked and allowed
connections as policy is implemented.

## Troubleshooting

For Kubernetes-specific troubleshooting information, view the [K8s Troubleshooting Guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/troubleshooting) guide.

For general Calico troubleshooting, see [Calico Troubleshooting](troubleshooting.md)
