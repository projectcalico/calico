---
title: Deploying Calico and Kubernetes on GCE
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/gce'
---

There are a number of solutions for deploying {{site.prodname}} and Kubernetes on GCE.  We recommend taking
a look at the following solutions and guides which install {{site.prodname}} for networking and network policy on GCE.

Make sure you've read the [GCE configuration guide](../../../reference/public-cloud/gce) for details on how to configure {{site.prodname}} and GCE.

#### Popular guides and tools

**[Kismatic Enterprise Toolkit][ket]** Fully-automated, production-grade Kubernetes operations on GCE and other clouds.

**[Kubernetes kube-up][kube-up]** deploys {{site.prodname}} on GCE using the same underlying open-source infrastructure as Google's GKE platform.

**[Kubespray][kubespray]** is a Kubernetes incubator project for deploying Kubernetes on GCE.

**[StackPointCloud][stackpoint]** lets you deploy a Kubernetes cluster with {{site.prodname}} to GCE in 3 steps using a web-based interface.

**[Typhoon][typhoon]** deploys free and minimal Kubernetes clusters with Terraform, for GCE and other platforms.

[ket]: https://apprenda.com/kismatic/
[kube-up]: http://kubernetes.io/docs/getting-started-guides/network-policy/calico/
[kubespray]: https://github.com/kubernetes-incubator/kubespray
[stackpoint]: https://stackpoint.io/#/
[typhoon]: https://typhoon.psdn.io/
[self-hosted]: hosted
[integration-guide]: integration
