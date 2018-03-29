---
title: Deploying Calico and Kubernetes on Azure
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/azure'
---

There are a number of solutions for deploying {{site.prodname}} and Kubernetes on Azure.  We recommend taking
a look at the following solutions and guides which install {{site.prodname}} for network policy on Azure.

Make sure you've read the [Azure configuration guide](../../../reference/public-cloud/azure) for details on how to configure {{site.prodname}} and Azure.

#### Popular guides and tools

**[ACS Engine][acs-engine]** configures and deploys Kubernetes clusters on Azure with an option to enable {{site.prodname}} policy.

#### More installation options

If the out-of-the-box solutions listed above don't meet your requirements, you can install {{site.prodname}} for Kubernetes
on Azure using one of our [self-hosted manifests][self-hosted], or by [integrating {{site.prodname}} with your own configuration management][integration-guide].

[acs-engine]: https://github.com/Azure/acs-engine/blob/master/docs/kubernetes.md
[self-hosted]: hosted
[integration-guide]: integration
