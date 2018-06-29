---
title: Installing Calico for policy and Amazon VPC CNI for networking
canonical_url: 'https://docs.projectcalico.org/master/getting-started/kubernetes/installation/amazon-vpc-cni-k8s'
---

## Before you begin

Ensure that you have a Kubernetes cluster on Amazon Web Services (AWS) that meets the
{{site.prodname}} [system requirements](../requirements). If you don't,
follow the steps in [using kubeadm to create a cluster](http://kubernetes.io/docs/getting-started-guides/kubeadm/).

Read the [Amazon documentation](https://github.com/aws/amazon-vpc-cni-k8s) for the VPC CNI plugin.

> **Note**: The Amazon VPC CNI plugin is currently in alpha and is not recommended for production.
{: .alert .alert-info}

## Installing {{site.prodname}} for policy and Amazon VPC CNI for networking

1. Issue the following command to install {{site.prodname}} and the necessary RBAC permissions.

   ```
   kubectl apply -f \
   https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/misc/aws-k8s-cni-calico.yaml
   ```
   > **Note**: You can also
   > [view the manifest in your browser](https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/misc/aws-k8s-cni-calico.yaml){:target="_blank"}.
   {: .alert .alert-info}
