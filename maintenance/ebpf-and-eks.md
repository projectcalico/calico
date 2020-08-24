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

eBPF (or "extended Berkeley Packet Filter"), is a technology that allows safe mini programs to be attached to various low-level hooks in the Linux kernel. eBPF has a wide variety of uses, including networking, security, and tracing. You’ll see a lot of non-networking projects leveraging eBPF, but for {{site.prodname}} our focus is on networking, and in particular, pushing the networking capabilities of the latest Linux kernels to the limit.

#### EKS

EKS is Amazon's managed Kubernetes offering; it has native support for {{site.prodname}} but, to use eBPF mode, a newer version of {{site.prodname}} must be installed.

### How to

- [Create a custom EKS AMI](#create-a-custom-eks-ami)
- [Create a cluster with the custom AMI](#create-a-cluster-with-the-custom-ami)
- [Adjust Calico settings for EKS](#adjust-calico-settings-for-eks)

#### Create a custom EKS AMI

By default, EKS uses Ubuntu 18.04 as its base image for EKS.  One way to create a suitable image for EKS is to:

1. Create an instance from the default EKS Ubuntu image.

2. Log into the instance with `ssh` and upgrade it to Ubuntu 20.04.

3. [Save the instance off as a custom AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html).

#### Create a cluster with the custom AMI

Using `eksctl`: start your cluster as normal, but use the `--node-ami` and `--node-ami-family` settings.  `--node-ami-family` should be set to `Ubuntu1804`, in spite of the upgrade.

Use the AWS VPC CNI plugin rather than the Calico CNI when setting up your cluster.  This is because EKS bundles an older version of Calico with EKS, which does not support eBPF mode. 

#### Adjust Calico settings for EKS

Before [enabling eBPF mode](./enabling-bpf), change the following Felix configuration parameter to prevent Felix from incorrectly detecting workload ENI interfaces as host interfaces:
```bash
calicoctl patch felixconfiguration default  '{"spec": {"bpfDataIfacePattern": "^(en[opsx].*|eth.*|tunl0$|wireguard.cali$)"}}'
```

