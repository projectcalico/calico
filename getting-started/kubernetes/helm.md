---
title: Installing Calico with Helm on Kubernetes
description: Install Calico on a Kubernetes cluster using Helm 3.
canonical_url: '/getting-started/kubernetes/helm'
---

### Big picture

This installs Calico on a Kubernetes cluster using Helm 3.

### Value

Helm charts are a way to package up an application for Kubernetes.  This can be thought of as similar to the way `apt` or `yum` packages applications for operating systems.  

Helm is also used by tools like ArgoCD to manage applications in a cluster, taking care of install, upgrade (and rollback if needed), etc. 

### Before you begin

- Install Helm 3.

- Make sure you have a kubernetes cluster that meets the following requirements:
  - kubernetes installed, but currently *without* a CNI plugin **OR** a cluster running a compatible CNI for Calico to run in policy-only mode 
  - x86-64, arm64, ppc64le, or s390x processors
  - RedHat Enterprise Linux 7.x+, CentOS 7.x+, Ubuntu 16.04+, or Debian 9.x+

- Configure `kubeconfig` to work with your cluster (check by running `kubectl get nodes`)

- Ensure that {{site.prodname}} can manage `cali` and `tunl` interfaces on the hosts.
  If NetworkManager is present on the hosts, refer to
  [Configure NetworkManager](../../maintenance/troubleshoot/troubleshooting#configure-networkmanager).

### Concepts

#### Operator based installation

This guide uses Helm 3 to install the Tigera operator which will install {{site.prodname}}. The operator provides lifecycle management for Calico
exposed via the Kubernetes API defined as a custom resource definition.

### How to

#### Download the helm chart

1. Go to the Calico [releases page](https://github.com/projectcalico/calico/releases) and find the release you want to install.

1. Download the chart from the release artifacts.  It will have a name like: `tigera-operator-{{page.version}}.0-1.tgz`

#### Create a Helm Customization

If you are installing on a cluster installed by EKS, GKE, AKS, Openshift or Docker Enterprise, you will need to customise this Helm chart.  

You might also need to do this if you want to customise TLS certificates.

Otherwise, this part can be skipped.

1. Run `helm show values tigera-operator-{{page.version}}.0-1.tgz` to see the values that can be customised in the chart

1. Create a `calico-config.yaml` file based on the output of `helm show values tigera-operator-{{page.version}}.0-1.tgz`.  

1. If you are installing on a cluster installed by EKS, GKE, AKS, Openshift or Docker Enterprise, set the `kubernetesProvider` as described in the [Installation reference](../../reference/installation/api#operator.tigera.io/v1.Provider)

#### Install {{site.prodname}}

1. Install the Tigera {{site.prodname}} operator and custom resource definitions using the Helm chart:

   ```
   helm install tigera-operator-{{page.version}}.0-1.tgz --generate-name 
   ```
   or if you created a `calico-config.yaml` above:
   ```
   helm install -f calico-config.yaml tigera-operator-{{page.version}}.0-1.tgz --generate-name 
   ```

1. Confirm that all of the pods are running with the following command.

   ```
   watch kubectl get pods -n calico-system
   ```

   Wait until each pod has the `STATUS` of `Running`.

   > **Note**: The Tigera operator installs resources in the `calico-system` namespace. Other install methods may use
   > the `kube-system` namespace instead.
   {: .alert .alert-info}

Congratulations! You have now installed {{site.prodname}} using the Helm 3 chart.

### Next steps

**Required**
- [Install and configure calicoctl](../clis/calicoctl/install)

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time](../../security/tutorials/kubernetes-policy-demo/kubernetes-demo)

