---
title: Deploying Calico and Kubernetes on AWS
canonical_url: https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/aws
---

There are a number of solutions for deploying Calico and Kubernetes on AWS.  We recommend taking
a look at the following solutions and guides which install Calico for networking and network policy on AWS.

Make sure you've read the [Calico AWS reference guide][aws-reference] for details on how to configure Calico and AWS.

#### Popular guides and tools

**[Heptio AWS Quickstart][heptio]** uses kubeadm and CloudFormation to build Kubernetes clusters on AWS using Calico
for networking and network policy enforcement.

**[Kops][kops]** is a popular Kubernetes project for launching production-ready clusters on AWS,
as well as other public and private cloud environments.

**[CoreOS Kubernetes][coreos]** documentation to learn how to install, run and use Kubernetes on CoreOS Container Linux on AWS.

**[StackPointCloud][stackpoint]** lets you deploy a Kubernetes cluster with Calico to AWS in 3 steps using a web-based interface.

**[Typhoon][typhoon]** deploys free and minimal Kubernetes clusters with Terraform, for AWS and other platforms.

#### More installation options

If the out-of-the-box solutions listed above don't meet your requirements, you can install Calico for Kubernetes
on AWS using one of our [self-hosted manifests][self-hosted], or by [integrating Calico with your own configuration management][integration-guide].

[heptio]: https://s3.amazonaws.com/quickstart-reference/heptio/latest/doc/heptio-kubernetes-on-the-aws-cloud.pdf
[kops]: https://github.com/kubernetes/kops/blob/master/docs/networking.md#calico-example-for-cni-and-network-policy
[stackpoint]: https://stackpoint.io/#/
[coreos]: https://coreos.com/kubernetes/docs/latest/
[typhoon]: https://typhoon.psdn.io/

[self-hosted]: hosted
[integration-guide]: integration

[aws-reference]: {{site.baseurl}}/{{page.version}}/reference/public-cloud/aws
