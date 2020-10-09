---
title: eBPF and EKS
description: Create a suitable EKS cluster to try the eBPF dataplane.
---

### Big picture

This guide explains how to set up an EKS cluster with a recent-enough Linux kernel to run the eBPF dataplane.  It assumes that you are familiar with AWS concepts such as building custom AMIs.

### Value

By default, EKS uses an older version of Linux for its base image, which is not compatible with {{site.prodname}}'s eBPF mode.  This guide explains how to set up a cluster with a newer base image.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **EKS Support**
- **calico/node**
- **eBPF dataplane**

### Concepts

#### eBPF

eBPF (or "extended Berkeley Packet Filter"), is a technology that allows safe mini programs to be attached to various 
low-level hooks in the Linux kernel. eBPF has a wide variety of uses, including networking, security, and tracing.
You’ll see a lot of non-networking projects leveraging eBPF, but for {{site.prodname}} our focus is on networking,
and in particular, pushing the networking capabilities of the latest Linux kernels to the limit.

#### EKS

EKS is Amazon's managed Kubernetes offering; it has native support for {{site.prodname}} but, to use eBPF mode, a 
newer version of {{site.prodname}} must be installed.

### How to

- [Create a an EKS cluster with a recent enough kernel](#create-a-custom-eks-ami)
- [Adjust Calico settings for EKS](#adjust-calico-settings-for-eks)

#### Create an EKS cluster with a recent enough kernel

By default, EKS uses Ubuntu 18.04 as its base image for EKS, which does not meet the kernel version requirement for 
eBPF mode.  

#### Option 1: Bottlerocket OS

The easiest way to start an EKS cluster that meets eBPF mode's requirements is to use Amazon's Bottlerocket OS, 
instead of the default.  Bottlerocket is a container-optimised OS with an emphasis on security and a recent enough 
kernel version to use eBPF mode. 


#### Option 2: Create a custom AMI

If you are familiar with the AMI creation process, it is also possible to create a custom AMI based on Ubuntu 20.04, 
which is suitable:

1. Create an instance from the default EKS Ubuntu image.

2. Log into the instance with `ssh` and upgrade it to Ubuntu 20.04.

3. [Save the instance off as a custom AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html) 
and make a note of the AMI ID

#### Create a cluster with the custom AMI

You must use the Calico CNI plugin rather than the AWS CNI plugin when setting up your cluster.  This is because EKS 
bundles an older version of Calico with EKS, which does not support eBPF mode.

Using `eksctl`: start your cluster as normal following the 
[EKS with Calico CNI install doc](../getting-started/kubernetes/managed-public-cloud/eks#install-eks-with-calico-networking), 
but when creating the nodegroup, add the `--node-ami` and `--node-ami-family` settings.

* `--node-ami` should be set to the AMI ID of the image built above.
* `--node-ami-family` should be set to `Ubuntu1804` (in spite of the upgrade).

For example:
```
eksctl create nodegroup --cluster my-calico-cluster --node-type t3.medium --node-ami auto --max-pods-per-node 100 --node-ami-family Ubuntu1804 --node-ami <AMI ID>
```

#### Adjust Calico settings for eBPF

When configuring {{site.prodname}} to connect to the API server, you should use the load balanced domain name created 
by EKS (and not the control plane node's instance IP, which may change).  One way to determine the domain name is to 
extract it from `kube-proxy`'s config map.
```
kubectl get cm -n kube-system kube-proxy -o yaml | grep server
```
should show the server name.

You can now [enable eBPF mode](./enabling-bpf).
