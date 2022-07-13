---
title: Install Calico for Windows on a Rancher Kubernetes Engine cluster
description: Install Calico for Windows on a Rancher RKE cluster.
canonical_url: '/getting-started/windows-calico/kubernetes/rancher'
---

### Big picture

Install {{site.prodnameWindows}} on a Rancher Kubernetes Engine (RKE) cluster.

### Value

Run Linux and Windows workloads on a RKE cluster with {{site.prodname}}.

### Before you begin

**Supported**

- RKE Kubernetes 1.20, 1.19, or 1.18

**Supported networking**

- BGP with no encapsulation
- VXLAN

**Required**

- An RKE cluster provisioned with {% include open-new-window.html text='no network plugin' url='https://rancher.com/docs/rke/latest/en/config-options/add-ons/network-plugins#disabling-deployment-of-a-network-plug-in' %}
but which otherwise meets the {{site.prodnameWindows}} Kubernetes [cluster requirements]({{site.baseurl}}/getting-started/windows-calico/kubernetes/requirements). This guide was tested with RKE v1.18.9.
- One or more Windows nodes that meet the [requirements]({{site.baseurl}}/getting-started/windows-calico/kubernetes/requirements).

### How to

The following steps will outline the installation of {{site.prodname}} networking on the RKE cluster, then the installation of {{site.prodnameWindows}} on the Windows nodes.

1. Install the Tigera {{site.prodname}} operator and custom resource definitions.

   ```
   kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml
   ```

1. Download the necessary Installation custom resource.

   ```bash
   wget {{site.data.versions.first.manifests_url}}/manifests/custom-resources.yaml
   ```

1. Update the `calicoNetwork` options, ensuring that the correct pod CIDR is set. (Rancher uses `10.42.0.0/16` by default.)
   Below are sample installations for VXLAN and BGP networking using the default Rancher pod CIDR:

   **VXLAN**

   ```
   apiVersion: operator.tigera.io/v1
   kind: Installation
   metadata:
     name: default
   spec:
     # Configures Calico networking.
     calicoNetwork:
       bgp: Disabled
       # Note: The ipPools section cannot be modified post-install.
       ipPools:
       - blockSize: 26
         cidr: 10.42.0.0/16
         encapsulation: VXLAN
         natOutgoing: Enabled
         nodeSelector: all()
   ```

   **BGP**

   ```
   apiVersion: operator.tigera.io/v1
   kind: Installation
   metadata:
     name: default
   spec:
     # Configures Calico networking.
     calicoNetwork:
       # Note: The ipPools section cannot be modified post-install.
       ipPools:
       - blockSize: 26
         cidr: 10.42.0.0/16
         encapsulation: None
         natOutgoing: Enabled
         nodeSelector: all()
   ```

   > **Note**: For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).
   {: .alert .alert-info}

1. Apply the updated custom resources:

   ```bash
   kubectl create -f custom-resources.yaml
   ```

1. [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

1. Configure strict affinity:
   ```bash
   calicoctl ipam configure --strictaffinity=true
   ```

1. Finally, follow the {{site.prodnameWindows}} [quickstart guide for Kubernetes]({{site.baseurl}}/getting-started/windows-calico/quickstart#install-calico-for-windows-manually)
   For VXLAN clusters, follow the instructions under the "Kubernetes VXLAN" tab. For BGP clusters, follow the instructions under the "Kubernetes BGP" tab.

   > **Note**: For Rancher default values for service CIDR and DNS cluster IP, see the {% include open-new-window.html text='Rancher kube-api service options' url='https://rancher.com/docs/rke/latest/en/config-options/services/#kubernetes-api-server-options' %}.
   {: .alert .alert-info}

1. Check the status of the nodes with `kubectl get nodes`. If you see that the Windows node has the status `Ready`, then you have a {{site.prodnameWindows}} on RKE cluster ready for Linux and Windows workloads!

### Next steps

- [Try the basic policy demo]({{site.baseurl}}/getting-started/windows-calico/demo)
- [Secure pods with {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)
