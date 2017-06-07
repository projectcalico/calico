---
title: Deploying Calico and Kubernetes on AWS
---

There are a number of solutions for deploying Calico and Kubernetes on AWS.  We recommend taking
a look at the following solutions and guides which install Calico for networking and network policy on AWS.

Make sure you've read the [Calico AWS reference guide][aws-reference] for details on how to configure Calico and AWS.

#### Popular guides and tools

**[Heptio AWS Quickstart][heptio]** uses kubeadm and CloudFormation to build Kubernetes clusters on AWS using Calico
for networking and network policy enforcement.


**[Kops][kops]** is a popular Kubernetes project for launching production-ready clusters on AWS,
as well as other public and private cloud environments.


**[kube-aws][kube-aws]** is a command-line tool by CoreOS to create, update, and destroy production-ready
container-linux based Kubernetes clusters on AWS.

#### More installation options

If the out-of-the-box solutions listed above don't meet your requirements, you can install Calico for Kubernetes
on AWS using one of our [self-hosted manifests][self-hosted], or by [integrating Calico with your own configuration management][integration-guide].

[heptio]: https://s3.amazonaws.com/quickstart-reference/heptio/latest/doc/heptio-kubernetes-on-the-aws-cloud.pdf
[kops]: https://github.com/kubernetes/kops/blob/master/docs/networking.md#calico-example-for-cni-and-network-policy
[kube-aws]: https://github.com/coreos/kube-aws/#getting-started

[self-hosted]: hosted
[integration-guide]: integration

[aws-reference]: {{site.baseurl}}/{{page.version}}/reference/public-cloud/aws
