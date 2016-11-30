---
title: Kubernetes
---

Calico drives pod connectivity and implements network policy for Kubernetes clusters.
Calico allows you to enforce fine-grained network security policy natively in Kubernetes.

Use the navigation bar on the left to view information on Calico for Kubernetes,
or continue reading for recommended guides to get started.

## Requirements

- The kube-proxy must be started in `iptables` proxy mode.  This is the default as of Kubernetes v1.2.0.

## Installation Guides

There are two ways to install Calico in Kubernetes.

#### [Hosted Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted)

Calico's Hosted Install uses Kubernetes Manifests to install Calico for Kubernetes, using Kubernetes.
Calico manifests ensure the necessary artifacts and configurations are added to each host, and the necessary services are started.

#### [Manual Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/)

This guide details how to add manually add Calico to an existing, stock Kubernetes cluster.


## Quickstart with "Calico-Ready" Clusters

Calico maintains sample cloud-config files which can be used to launch a Calico-ready Kubernetes cluster.

The following guides walk through launching a CoreOS cluster using these
cloud-config scripts (locally and on various cloud providers), and then
perform a Calico hosted installation on top.

#### [CoreOS Vagrant]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/vagrant/)

This guide uses Vagrant and VirtualBox to locally run a Kubernetes
cluster with Calico.

#### [AWS Tutorial]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/aws)

This guide covers launching a Kubernetes cluster on AWS with Calico.

#### [GCE]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/gce)

This guide covers launching a Kubernetes cluster on GCE with Calico.

## Tutorials

The following tutorials walk through policy configurations for Calico in Kubernetes.

Before following these tutorials, ensure you've used the above guides to launch
a Kubernetes cluster with Calico installed.

#### [Simple Policy](tutorials/simple-policy)

The Simple Policy Demo shows how to use Calico to secure a simple two-tier application in kubernetes.

#### [Stars Demo](tutorials/stars-policy/)

The Stars Demo features a UI which actively shows blocked and allowed
connections as policy is implemented.

## Troubleshooting

For Kubernetes-specific troubleshooting information, view the [k8s troubleshooting guide]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/troubleshooting) guide.
