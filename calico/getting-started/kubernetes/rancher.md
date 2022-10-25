---
title: Install Calico on a Rancher Kubernetes Engine cluster
description: Install Calico on a Rancher Kubernetes Engine cluster.
canonical_url: '/getting-started/kubernetes/rancher'
---

### Big picture

Install {{site.prodname}} as the required CNI for networking and/or network policy on Rancher-deployed clusters.

### Concepts

{{site.prodname}} supports the Calico CNI with Calico network policy:

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:Kubernetes' %}

### Before you begin

**Required**

- A compatible {% include open-new-window.html text='Rancher Kubernetes Engine cluster' url='https://rancher.com/docs/rke/latest/en/' %} with version 1.2.9 and later
  - Configure your cluster with a {% include open-new-window.html text='Cluster Config File' url='https://rancher.com/docs/rancher/v2.x/en/cluster-provisioning/rke-clusters/options/#cluster-config-file' %} and specify {% include open-new-window.html text='no network plugin' url='https://rancher.com/docs/rke/latest/en/config-options/add-ons/network-plugins/' %} by setting `plugin: none` under `network` in your configuration file.

- RKE cluster meets the [{{side.prodname}} requirements]({{site.baseurl}}/getting-started/kubernetes/requirements)

- A `kubectl` environment with access to your cluster
  - Use {% include open-new-window.html text='Rancher kubectl Shell' url='https://rancher.com/docs/rancher/v2.x/en/cluster-admin/cluster-access/kubectl/' %} for access
  - Ensure you have the {% include open-new-window.html text='Kubeconfig file that was generated when you created the cluster' url='https://rancher.com/docs/rke/latest/en/installation/#save-your-files' %}.

- If using a Kubeconfig file locally, {% include open-new-window.html text='install and set up the Kubectl CLI tool' url='https://kubernetes.io/docs/tasks/tools/install-kubectl/' %}.

### How to

- [Install {{site.prodname}}](#install-calico)

#### Install {{site.prodname}}

1. Install the Tigera {{site.prodname}} operator and custom resource definitions.

   ```
   kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml
   ```

1. Install {{site.prodname}} by creating the necessary custom resource. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

   ```
   kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/custom-resources.yaml
   ```

   > **Note**: Before creating this manifest, read its contents and make sure its settings are correct for your environment. For example,
   > you may need to change the default IP pool CIDR to match your pod network CIDR. Rancher uses `10.42.0.0/16` by default.
   {: .alert .alert-info}

   > **Note**: If you are installing {{site.prodname}} on Windows nodes in this cluster, please see the [{{site.prodnameWindows}} for RKE]({{site.baseurl}}/getting-started/windows-calico/kubernetes/rancher) installation instructions.
   {: .alert .alert-info}

1. Confirm that all of the pods are running with the following command.

   ```
   watch kubectl get pods -n calico-system
   ```

   Wait until each pod has the `STATUS` of `Running`.

Congratulations! You now have an RKE cluster running {{site.prodname}}

### Next steps

**Required**
- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time](../../security/tutorials/kubernetes-policy-demo/kubernetes-demo)
