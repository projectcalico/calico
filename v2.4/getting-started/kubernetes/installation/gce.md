---
title: Deploying Calico and Kubernetes on GCE
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/gce'
---

There are a number of solutions for deploying Calico and Kubernetes on GCE.  We recommend taking
a look at the following solutions and guides which install Calico for networking and network policy on GCE.

Make sure you've read the [Calico GCE reference guide][gce-reference] for details on how to configure Calico and GCE.

#### Popular guides and tools

**[Kismatic Enterprise Toolkit][ket]** Fully-automated, production-grade Kubernetes operations on GCE and other clouds.

**[Kubernetes kube-up][kube-up]** deploys Calico on GCE using the same underlying open-source infrastructure as Google's GKE platform.

**[Kubespray][kubespray]** is a Kubernetes incubator project for deploying Kubernetes on GCE.

**[StackPointCloud][stackpoint]** lets you deploy a Kubernetes cluster with Calico to GCE in 3 steps using a web-based interface.

#### More installation options

If the out-of-the-box solutions listed above don't meet your requirements, you can install Calico for Kubernetes
on GCEusing one of our [self-hosted manifests][self-hosted], or by [integrating Calico with your own configuration management][integration-guide].

[ket]: https://apprenda.com/kismatic/
[kube-up]: http://kubernetes.io/docs/getting-started-guides/network-policy/calico/
[kubespray]: https://github.com/kubernetes-incubator/kubespray
[stackpoint]: https://stackpoint.io/#/

[self-hosted]: hosted
[integration-guide]: integration

[gce-reference]: {{site.baseurl}}/{{page.version}}/reference/public-cloud/gce
