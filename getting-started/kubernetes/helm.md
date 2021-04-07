---
title: Install using Helm
description: Install Calico on a Kubernetes cluster using Helm 3.
canonical_url: '/getting-started/kubernetes/helm'
---

### Big picture

Install {{site.prodname}} on a Kubernetes cluster using Helm 3.

### Value

Helm charts are a way to package up an application for Kubernetes (similar to `apt` or `yum` for operating systems). Helm is also used by tools like ArgoCD to manage applications in a cluster, taking care of install, upgrade (and rollback if needed), etc.

Helm is also used by tools like ArgoCD to manage applications in a cluster, taking care of install, upgrade (and rollback if needed), etc. 

### Before you begin
**Required**

- Install Helm 3
- Kubernetes cluster meets these requirements:
  - Kubernetes is installed *without* a CNI plugin **OR** cluster is running a compatible CNI for {{site.prodname}} to run in policy-only mode 
  - x86-64, arm64, ppc64le, or s390x processors
  - RedHat Enterprise Linux 7.x+, CentOS 7.x+, Ubuntu 16.04+, or Debian 9.x+
- `kubeconfig` is configured to work with your cluster (check by running `kubectl get nodes`)
- {{site.prodname}} can manage `cali` and `tunl` interfaces on the hosts.
  If NetworkManager is present on the hosts, refer to
  [Configure NetworkManager](../../maintenance/troubleshoot/troubleshooting#configure-networkmanager).

### Concepts

#### Operator based installation

In this guide, you install the Tigera {{site.prodname}} operator and custom resource definitions using the Helm 3 chart. The Tigera operator provides lifecycle management for {{site.prodname}} exposed via the Kubernetes API.
exposed via the Kubernetes API defined as a custom resource definition.

### How to

#### Download the Helm chart

1. [Download the chart for the latest release](https://github.com/projectcalico/calico/releases/download/{{site.data.versions[0].title}}/tigera-operator-{{site.data.versions[0].title}}-{{site.data.versions[0].chart.version}}.tgz) from the release artifacts.  
**OR**   
Go to the {{site.prodname}} [releases page](https://github.com/projectcalico/calico/releases) and find the release you want to install. The chart will be in the release artifacts and will have a name like: `tigera-operator-{{site.data.versions[0].title}}-{{site.data.versions[0].chart.version}}.tgz`

#### Customize the Helm chart
If you are installing on a cluster installed by EKS, GKE, AKS or Docker Enterprise, or you need to customize TLS certificates, you **must** customize this Helm chart by creating a `values.yaml` file.

Otherwise, you can skip this step.

1. If you are installing on a cluster installed by EKS, GKE, AKS or Docker Enterprise, set the `kubernetesProvider` as described in the [Installation reference](../../reference/installation/api#operator.tigera.io/v1.Provider).  For example:
```
echo '{installation.kubernetesProvider: EKS}' > values.yaml
```
1. Add any other customizations you require to `values.yaml`.  You might like to refer to the [helm docs](https://helm.sh/docs/) or run 
   ```
   helm show values tigera-operator-{{site.data.versions[0].title}}-{{site.data.versions[0].chart.version}}.tgz
   ``` 
   to see the values that can be customized in the chart.

#### Install {{site.prodname}}

1. Install the Tigera {{site.prodname}} operator and custom resource definitions using the Helm chart:

   ```
   helm install calico tigera-operator-{{site.data.versions[0].title}}-{{site.data.versions[0].chart.version}}.tgz 
   ```
   or if you created a `values.yaml` above:
   ```
   helm install calico tigera-operator-{{site.data.versions[0].title}}-{{site.data.versions[0].chart.version}}.tgz -f values.yaml
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
