---
title: Quickstart for Calico on Kubernetes
description: Install Calico on a single-host Kubernetes cluster for testing or development in under 15 minutes.
canonical_url: '/getting-started/kubernetes/quickstart'
---

### Big picture

This quickstart gets you a single-host Kubernetes cluster with {{site.prodname}} in approximately 15 minutes.

### Value

Use this quickstart to quickly and easily try {{site.prodname}} features. To deploy a cluster suitable for production, refer to [{{site.prodname}} on Kubernetes]({{ site.baseurl }}/getting-started/kubernetes/).

### Before you begin

- Make sure you have a linux host that meets the following requirements:
  - x86-64, arm64, ppc64le, or s390x processor
  - 2CPU
  - 2GB RAM
  - 10GB free disk space
  - RedHat Enterprise Linux 7.x+, CentOS 7.x+, Ubuntu 16.04+, or Debian 9.x+

- Ensure that {{site.prodname}} can manage `cali` and `tunl` interfaces on the host.
  If NetworkManager is present on the host, refer to
  [Configure NetworkManager](../../maintenance/troubleshoot/troubleshooting#configure-networkmanager).

### Concepts

#### Operator based installation

This quickstart guide uses the Tigera operator to install {{site.prodname}}. The operator provides lifecycle management for Calico
exposed via the Kubernetes API defined as a custom resource definition.

> **Note**: It is also possible to install Calico without an operator using Kubernetes manifests directly.
> For platforms and guides that do not use the Tigera operator, you may notice some differences in the steps and Kubernetes
> resources compared to those presented in this guide.
{: .alert .alert-info}

### How to

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:kubernetes' %}

#### Create a single-host Kubernetes cluster

1. {% include open-new-window.html text='Follow the Kubernetes instructions to install kubeadm' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/' %}

   > **Note**: After installing kubeadm, do not power down or restart
   the host. Instead, continue directly to the next step.
   {: .alert .alert-info}

1. As a regular user with sudo privileges, open a terminal on the host that you installed kubeadm on.

1. Initialize the master using the following command.

   ```
   sudo kubeadm init --pod-network-cidr=192.168.0.0/16
   ```

   > **Note**: If 192.168.0.0/16 is already in use within your network you must select a different pod network
   > CIDR, replacing 192.168.0.0/16 in the above command.
   {: .alert .alert-info}

1. Execute the following commands to configure kubectl (also returned by `kubeadm init`).

   ```
   mkdir -p $HOME/.kube
   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
   sudo chown $(id -u):$(id -g) $HOME/.kube/config
   ```

#### Install {{site.prodname}}

1. Install the Tigera {{site.prodname}} operator and custom resource definitions.

   ```
   kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
   ```

   > **Note**: Due to the large size of the CRD bundle, `kubectl apply` might exceed request limits. Instead, use `kubectl create` or `kubectl replace`.
   {: .alert .alert-info}

1. Install {{site.prodname}} by creating the necessary custom resource. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

   ```
   kubectl create -f {{ "/manifests/custom-resources.yaml" | absolute_url }}
   ```

   > **Note**: Before creating this manifest, read its contents and make sure its settings are correct for your environment. For example,
   > you may need to change the default IP pool CIDR to match your pod network CIDR.
   {: .alert .alert-info}

1. Confirm that all of the pods are running with the following command.

   ```
   watch kubectl get pods -n calico-system
   ```

   Wait until each pod has the `STATUS` of `Running`.

   > **Note**: The Tigera operator installs resources in the `calico-system` namespace. Other install methods may use
   > the `kube-system` namespace instead.
   {: .alert .alert-info}

1. Remove the taints on the master so that you can schedule pods on it.

   ```
   kubectl taint nodes --all node-role.kubernetes.io/control-plane- node-role.kubernetes.io/master-
   ```

   It should return the following.

   ```
   node/<your-hostname> untainted
   ```
   {: .no-select-button}

1. Confirm that you now have a node in your cluster with the following command.

   ```
   kubectl get nodes -o wide
   ```

   It should return something like the following.

   ```
   NAME              STATUS   ROLES    AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION    CONTAINER-RUNTIME
   <your-hostname>   Ready    master   52m   v1.12.2   10.128.0.28   <none>        Ubuntu 18.04.1 LTS   4.15.0-1023-gcp   docker://18.6.1
   ```
   {: .no-select-button}

Congratulations! You now have a single-host Kubernetes cluster with {{site.prodname}}.

### Next steps

**Required**
- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time](../../security/tutorials/kubernetes-policy-demo/kubernetes-demo)

