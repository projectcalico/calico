---
title: Installing Calico on Kubernetes
canonical_url: https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/
---

We provide a number of manifests to get you up and running with {{site.prodname}} in
just a few steps. Refer to the section that corresponds to your desired networking
for instructions.

- [Installing {{site.prodname}} for policy and networking (recommended)](calico)

- [Installing {{site.prodname}} for policy and flannel for networking](flannel)

- [Installing {{site.prodname}} for policy (advanced)](other)

After installing {{site.prodname}}, you can [enable application layer policy](app-layer-policy).
Enabling application layer policy also secures workload-to-workload communications with mutual 
TLS authentication.

Should you wish to modify the manifests before applying them, refer to
[Customizing the manifests](config-options).

If you prefer not to use Kubernetes to start the {{site.prodname}} services, refer to the
[Integration guide](integration).

## Third-party solutions

Several third-party vendors also provide tools to install Kubernetes with {{site.prodname}} in a variety of
environments.

| Name                                 | Description |
|--------------------------------------|-------------|
| [ACS Engine][acs-engine]             | Deploys Kubernetes clusters on Azure with an option to enable {{site.prodname}} policy. |
| [Google Container Engine][gke]       | A managed Kubernetes environment by Google using {{site.prodname}} for network policy. |
| [Heptio AWS Quickstart][heptio]      | Uses kubeadm and CloudFormation to build Kubernetes clusters on AWS using {{site.prodname}} for networking and network policy enforcement. |
| [IBM Cloud Kubernetes Service][ibmk] | A managed Kubernetes environment by IBM using {{site.prodname}} for networking and network policy enforcement. |
| [Kismatic Enterprise Toolkit][ket]   | Fully-automated, production-grade Kubernetes operations on AWS and other clouds. |
| [Kops][kops]                         | A popular Kubernetes project for launching production-ready clusters on AWS, as well as other public and private cloud environments. |
| [Kubernetes kube-up][kube-up]        | Deploys {{site.prodname}} on GCE using the same underlying open-source infrastructure as Google's GKE platform. |
| [Kubespray][kubespray]               | A Kubernetes project for deploying Kubernetes with Ansible |
| [StackPointCloud][stackpoint]        | Deploys a Kubernetes cluster with {{site.prodname}} to AWS in 3 steps using a web-based interface. |
| [Typhoon][typhoon]                   | Deploys free and minimal Kubernetes clusters with Terraform. |

[acs-engine]: https://github.com/Azure/acs-engine/blob/master/docs/kubernetes.md
[gke]: https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy
[heptio]: https://s3.amazonaws.com/quickstart-reference/heptio/latest/doc/heptio-kubernetes-on-the-aws-cloud.pdf
[ibmk]: https://www.ibm.com/cloud/container-service/
[ket]: https://apprenda.com/kismatic/
[kops]: https://github.com/kubernetes/kops/blob/master/docs/networking.md#calico-example-for-cni-and-network-policy
[kubespray]: https://github.com/kubernetes-incubator/kubespray
[kube-up]: http://kubernetes.io/docs/getting-started-guides/network-policy/calico/
[stackpoint]: https://stackpoint.io/#/
[typhoon]: https://typhoon.psdn.io/
