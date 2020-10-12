---
title: Creating an EKS cluster for eBPF mode
description: Create an EKS cluster with a newer kernel, suitable for eBPF mode.
---

### Big picture

This guide explains how to set up an EKS cluster with a recent-enough Linux kernel to run the eBPF dataplane.  

### Value

By default, EKS uses an older version of the Linux kernel in its base image, which is not compatible with {{site.prodname}}'s 
eBPF mode.  This guide explains how to set up a cluster using a base image with a recent-enough kernel.

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

EKS is Amazon's managed Kubernetes offering.

> **Note**: The EKS docs include instructions for installing {{site.prodname}} with the AWS VPC CNI.  The current 
> version of those docs uses an older version of {{site.prodname}} that does not include the GA version of eBPF mode.
> The instructions below guide you through installing {{site.prodname}} with the {{site.prodname}} CNI.
{: .alert .alert-info}

### How to

- [Create a an EKS cluster with a recent enough kernel](#create-a-custom-eks-ami)
- [Adjust Calico settings for EKS](#adjust-calico-settings-for-eks)

#### Create an EKS cluster with a recent enough kernel

By default, EKS uses Ubuntu 18.04 as its base image for EKS, which does not meet the kernel version requirement for 
eBPF mode.  Below, we give a couple of options for how to get the cluster running with a suitable kernel:


{% tabs tab-group:grp1 %}
<label:Bottlerocket,active:true>
<%

#### Option 1: Bottlerocket

The easiest way to start an EKS cluster that meets eBPF mode's requirements is to use Amazon's 
[Bottlerocket](https://aws.amazon.com/bottlerocket/) OS, instead of the default.  Bottlerocket is a 
container-optimised OS with an emphasis on security; it has a recent enough kernel to use eBPF mode.

* To create a 2-node test cluster with a Bottlerocket node group, run the command below.  It is important to use the config-file
  approach to creating a cluster in order to set the additional IAM permissions for Bottlerocket.

  ```
  eksctl create cluster --config-file - <<EOF
  apiVersion: eksctl.io/v1alpha5
  kind: ClusterConfig
  metadata:
    name: my-calico-cluster
    region: us-west-2
    version: '1.17'
  nodeGroups:
    - name: ng-my-calico-cluster
      instanceType: t3.medium
      minSize: 0
      maxSize: 2
      desiredCapacity: 2
      amiFamily: Bottlerocket
      iam:
        attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
  EOF
  ```
 
* Then, remove the AWS CNI DaemonSet: 
  ```bash
  kubectl delete daemonset -n kube-system aws-node
  ```

* Install {{site.prodname}} in VXLAN mode using the manifest:
  ```bash
  kubectl apply -f {{ "/manifests/calico-vxlan.yaml" | absolute_url }}
  ```
  
  > **Note**: This will use the {{site.prodname}} CNI plugin (rather than the AWS VPC CNI plugin).  We recommend
  > sticking the {{site.prodname}} CNI plugin in this release because there are a couple of known issues with the
  > combination of eBPF mode and the AWS VPC CNI plugin. Fixes for those issues are in progress.
  {: .alert .alert-info}
                                                                                                                                                          
%>
<label:Custom AMI>
<%


#### Option 2: Create a custom AMI

If you are familiar with the AMI creation process, it is also possible to create a custom AMI based on Ubuntu 20.04, 
which is suitable:

* Create an instance from the default EKS Ubuntu image.

* Log into the instance with `ssh` and upgrade it to Ubuntu 20.04.

* [Save the instance off as a custom AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html) 
  and make a note of the AMI ID

* Using `eksctl`: start your cluster as normal following the 
  [EKS with Calico CNI install doc](../getting-started/kubernetes/managed-public-cloud/eks#install-eks-with-calico-networking), 
  but when creating the nodegroup, add the `--node-ami` and `--node-ami-family` settings.

  * `--node-ami` should be set to the AMI ID of the image built above.
  * `--node-ami-family` should be set to `Ubuntu1804` (in spite of the upgrade).

  For example:
  ```
  eksctl create nodegroup --cluster my-calico-cluster --node-type t3.medium --node-ami auto --max-pods-per-node 100 --node-ami-family Ubuntu1804 --node-ami <AMI ID>
  ```
  
  > **Note**: We recommend that you use the {{site.prodname}} CNI plugin (rather than the AWS VPC CNI plugin)
  > because there are a couple of known issues with the combination of eBPF mode and the AWS VPC CNI plugin.
  > Fixes for those issues are in progress.
  {: .alert .alert-info}
%>
{% endtabs %}

* Continue with the instructions in the main [Enabling eBPF page](./enabling-bpf).  

  When configuring {{site.prodname}} to connect to the API server, use the load balanced domain name created by EKS.
  One way to determine the domain name is to extract it from `kube-proxy`'s config map:
  ```
  kubectl get cm -n kube-system kube-proxy -o yaml | grep server
  ```
  should show the server name, for example:
  ```
      server: https://d881b853ae9313e00302a84f1e346a77.gr7.us-west-2.eks.amazonaws.com
  ```
  In that case you should use `d881b853ae9313e00302a84f1e346a77.gr7.us-west-2.eks.amazonaws.com` for `KUBERNETES_SERVICE_HOST`
  and `443` (the default for HTTPS) for `KUBERNETES_SERVICE_PORT` when creating the config map.
