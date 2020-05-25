---
title: Install Calico networking and network policy for on-premises deployments
description: Install Calico networking and network policy for on-premises deployments.
---

### Big picture

Install {{site.prodname}} to provide both networking and network policy for self-managed on-premises deployments.

### Value

**{{site.prodname}} networking** and **network policy** are a powerful choice for a CaaS implementation. If you have the networking infrastructure and resources to manage Kubernetes on-premises, installing the full {{site.prodname}} product provides the most customization and control.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **Typha**

### Concepts

#### {{site.prodname}} manifests

{{site.prodname}} provides manifests for easy customization. Each manifest contains the necessary resources for installing {{site.prodname}} on each node in your Kubernetes cluster. You may want to [customize the {{site.prodname}} manifests]({{site.baseurl}}/getting-started/kubernetes/installation/config-options) before installing {{site.prodname}} on nodes.

### Before you begin...

- Ensure that your Kubernetes cluster meets [requirements]({{site.baseurl}}/getting-started/kubernetes/requirements).
  If you do not have a cluster, see {% include open-new-window.html text='Installing kubeadm' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/' %}.
- If you are using CoreOS, [make this required change to manifests]({{site.baseurl}}/reference/faq#are-the-calico-manifests-compatible-with-coreos).

### How to

- [Determine your datastore](#determine-your-datastore)
- [Install Calico on nodes](#install-calico-on-nodes)

#### Determine your datastore

{{site.prodname}} supports both **Kubernetes API datastore (kdd)** and **etcd** datastores. The **Kubernetes API datastore** is recommended for on-premises deployments, and supports only Kubernetes workloads; **etcd** is the best datastore for hybrid deployments.

#### Install Calico on nodes

Based on your datastore and number of nodes, select a link below to install {{site.prodname}}.

>**Note**: The option, **Kubernetes API datastore, more than 50 nodes** provides scaling using [Typha daemon]({{site.baseurl}}/reference/typha/). Typha is not included for etcd because etcd already handles many clients so using Typha is redundant and not recommended.
{: .alert .alert-info}

- [Install Calico with Kubernetes API datastore, 50 nodes or less](#install-calico-with-kubernetes-api-datastore-50-nodes-or-less)
- [Install Calico with Kubernetes API datastore, more than 50 nodes](#install-calico-with-kubernetes-api-datastore-more-than-50-nodes)
- [Install Calico with etcd datastore](#install-calico-with-etcd-datastore)

##### Install Calico with Kubernetes API datastore, 50 nodes or less

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{ "/manifests/calico.yaml" | absolute_url }} -O
   ```
{% include content/pod-cidr-sed.md yaml="calico" %}
1. Customize the manifest as necessary.
1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f calico.yaml
   ```

##### Install Calico with Kubernetes API datastore, more than 50 nodes

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{ "/manifests/calico-typha.yaml" | absolute_url }} -o calico.yaml
   ```
{% include content/pod-cidr-sed.md yaml="calico" %}
1. Modify the replica count to the desired number in the `Deployment` named, `calico-typha`.

   ```
   apiVersion: apps/v1beta1
   kind: Deployment
   metadata:
     name: calico-typha
     ...
   spec:
     ...
     replicas: <number of replicas>
    ```
    {: .no-select-button}

    We recommend at least one replica for every 200 nodes, and no more than
    20 replicas. In production, we recommend a minimum of three replicas to reduce
    the impact of rolling upgrades and failures. The number of replicas should
    always be less than the number of nodes, otherwise rolling upgrades will stall.
    In addition, Typha only helps with scale if there are fewer Typha instances than
    there are nodes.

    >**Warning**: If you set `typha_service_name` and set the Typha deployment replica
    >count to 0, Felix will not start.
    {: .alert .alert-info}

1. Customize the manifest if desired.
1. Apply the manifest.

   ```bash
   kubectl apply -f calico.yaml
   ```

##### Install Calico with etcd datastore

1. Download the {{site.prodname}} networking manifest for etcd.

   ```bash
   curl {{ "/manifests/calico-etcd.yaml" | absolute_url }} -o calico.yaml
   ```
{% include content/pod-cidr-sed.md yaml="calico" %}
1. In the `ConfigMap` named, `calico-config`, set the value of `etcd_endpoints` to the IP address and port of your etcd server.
    > **Tip**: You can specify more than one `etcd_endpoint` using commas as delimiters.
   {: .alert .alert-info}
1. Customize the manifest if desired.
1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f calico.yaml
   ```

### Next steps

**Tools**

- [Install and configure calicoctl]({{site.baseurl}}/getting-started/clis/calicoctl/install)

**Networking**

- If you are using the default BGP networking with full-mesh node-to-node peering with no encapsulation, go to [Configure BGP peering]({{site.baseurl}}/networking/bgp) to get traffic flowing between pods.
- If you are unsure about networking options, or want to implement encapsulation (overlay networking), see [Determine best networking option]({{site.baseurl}}/networking/determine-best-networking).

**Security**

- [Secure Calico component communications]({{site.baseurl}}/security/comms/crypto-auth)
- [Secure hosts by installing Calico on hosts]({{site.baseurl}}/getting-started/bare-metal/about)
- [Secure pods with Calico network policy]({{site.baseurl}}/security/calico-network-policy)
- If you are using {{site.prodname}} with Istio service mesh, get started here: [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy)
