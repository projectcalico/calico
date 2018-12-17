---
title: Installing Calico on Kubernetes
canonical_url: https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/
---

Calico can be installed on a Kubernetes cluster in a number of configurations.  This document
gives an overview of the most popular approaches, and provides links to each for more detailed
information.

## Requirements

Calico can run on any Kubernetes cluster which meets the following criteria.

- The kubelet must be configured to use CNI network plugins (e.g `--network-plugin=cni`).
- The kube-proxy must be started in `iptables` proxy mode.  This is the default as of Kubernetes v1.2.0.
- The kube-proxy must be started without the `--masquerade-all` flag, which conflicts with Calico policy.
- The Kubernetes NetworkPolicy API requires at least Kubernetes version v1.3.0.
- When RBAC is enabled, the proper accounts, roles, and bindings must be defined
  and utilized by the Calico components.  Examples exist for both the [etcd](rbac.yaml) and
  [kubernetes api](hosted/rbac-kdd.yaml) datastores.


## [Calico Hosted Install](hosted)

Installs the Calico components as a DaemonSet entirely using Kubernetes manifests through a single
kubectl command.  This method is supported for Kubernetes versions >= v1.4.0.

## [Custom Installation](integration)

In addition to the hosted approach above, the Calico components can also be installed using your
own orchestration mechanisms (e.g ansible, chef, bash, etc)

Follow the [integration guide](integration) if you're using a Kubernetes version < v1.4.0, or if you would like
to integrate Calico into your own installation or deployment scripts.

## Third-party solutions

Several third-party vendors also provide tools to install Kubernetes with {{site.prodname}} in a variety of
environments.

| Name                                 | Description |
|--------------------------------------|-------------|
| [ACS Engine][acs-engine]             | Deploys Kubernetes clusters on Azure with an option to enable {{site.prodname}} policy. |
| [Google Container Engine][gke]       | A managed Kubernetes environment by Google using {{site.prodname}} for network policy. |
| [Heptio AWS Quickstart][heptio]      | Uses kubeadm and CloudFormation to build Kubernetes clusters on AWS using {{site.prodname}} for networking and network policy enforcement. |
| [IBM Cloud Kubernetes Service][ibmk] | A managed Kubernetes environment by IBM using {{site.prodname}} for networking and network policy enforcement. |
| [Kops][kops]                         | A popular Kubernetes project for launching production-ready clusters on AWS, as well as other public and private cloud environments. |
| [Kubernetes kube-up][kube-up]        | Deploys {{site.prodname}} on GCE using the same underlying open-source infrastructure as Google's GKE platform. |
| [Kubespray][kubespray]               | A Kubernetes project for deploying Kubernetes on GCE. |
| [StackPointCloud][stackpoint]        | Deploys a Kubernetes cluster with {{site.prodname}} to AWS in 3 steps using a web-based interface. |
| [Typhoon][typhoon]                   | Deploys free and minimal Kubernetes clusters with Terraform. |

[acs-engine]: https://github.com/Azure/acs-engine/blob/master/docs/kubernetes.md
[gke]: https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy
[heptio]: https://s3.amazonaws.com/quickstart-reference/heptio/latest/doc/heptio-kubernetes-on-the-aws-cloud.pdf
[ibmk]: https://www.ibm.com/cloud/container-service/
[kops]: https://github.com/kubernetes/kops/blob/master/docs/networking.md#calico-example-for-cni-and-network-policy
[kubespray]: https://github.com/kubernetes-incubator/kubespray
[kube-up]: http://kubernetes.io/docs/getting-started-guides/network-policy/calico/
[stackpoint]: https://stackpoint.io/#/
[typhoon]: https://typhoon.psdn.io/
