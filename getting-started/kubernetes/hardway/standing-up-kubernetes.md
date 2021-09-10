---
title: Stand up Kubernetes
description: Get a Kubernetes cluster up and running.
canonical_url: '/getting-started/kubernetes/hardway/standing-up-kubernetes'
---

We will install {{site.prodname}} on a Kubernetes cluster. To demonstrate a highly available {{site.prodname}} control plane, we will use five nodes in this guide. This lab walks you through provisioning a Kubernetes cluster in AWS using kubeadm.

## Provision EC2 Nodes

1. Provision five nodes
    1. Ubuntu 20.04 LTS - Focal
    1. T2.medium
    1. Ensure the instances are in the same subnet, and security group policy allows them communicate freely with one another.
    1. Disable Source / Destination Checks on the Elastic Network Interface for each instance
1. Install Docker on each node
    1. `sudo apt update`
    1. `sudo apt install docker.io`
    1. `sudo systemctl enable docker`

## Install Kubernetes

1. Install kubeadm, kubelet, kubectl by following {% include open-new-window.html text='official documentation' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl' %}
1. Choose one node as your Kubernetes master. On that node
   `sudo kubeadm init --pod-network-cidr=192.168.0.0/16`

   The Kubernetes `pod-network-cidr` is the IP prefix for all pods in the Kubernetes cluster. This range must not clash with other networks in your VPC.
1. On all other nodes
   `sudo kubeadm join <output from kubeadm init>`
1. Copy admin credentials
1. Test Access
    1. Run

       `kubectl get nodes`

       Verify all nodes have joined. At this point nodes have joined but they are in `NotReady` state, because Kubernetes can't find a networking provider and configuration.

## Next

[The Calico datastore](./the-calico-datastore)
