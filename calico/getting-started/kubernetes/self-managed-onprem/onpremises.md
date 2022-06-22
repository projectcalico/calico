---
title: Install Calico networking and network policy for on-premises deployments
description: Install Calico networking and network policy for on-premises deployments.
---

### Big picture

Install {{site.prodname}} to provide both networking and network policy for self-managed on-premises deployments.

### Value

**{{site.prodname}} networking** and **network policy** are a powerful choice for a CaaS implementation. If you have the networking infrastructure and resources to manage Kubernetes on-premises, installing the full {{site.prodname}} product provides the most customization and control.

### Concepts

#### {{site.prodname}} operator

{{site.prodname}} is installed by an operator which manages the installation, upgrade, and general lifecycle of a {{site.prodname}} cluster. The operator is
installed directly on the cluster as a Deployment, and is configured through one or more custom Kubernetes API resources.

#### {{site.prodname}} manifests

{{site.prodname}} can also be installed using raw manifests as an alternative to the operator. The manifests contain the necessary resources for installing {{site.prodname}} on each node in your Kubernetes cluster. Using manifests is not recommended as they cannot automatically manage the lifecycle of the {{site.prodname}} as the operator does. However, manifests may be useful for clusters that require highly specific modifications to the underlying Kubernetes resources.

### Before you begin...

- Ensure that your Kubernetes cluster meets [requirements]({{site.baseurl}}/getting-started/kubernetes/requirements).
  If you do not have a cluster, see {% include open-new-window.html text='Installing kubeadm' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/' %}.

### How to

- [Install Calico](#install-calico)

#### Install Calico

{% tabs %}
  <label:Operator,active:true>
<%

1. First, install the operator on your cluster.

   ```
   kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml
   ```

1. Download the custom resources necessary to configure {{site.prodname}}

   ```
   curl {{site.data.versions.first.manifests_url}}/manifests/custom-resources.yaml -O
   ```
   
   If you wish to customize the {{site.prodname}} install, customize the downloaded custom-resources.yaml manifest locally.

1. Create the manifest in order to install {{site.prodname}}.
   
   ```
   kubectl create -f custom-resources.yaml
   ```

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:Kubernetes' %}

%>
  <label:Manifest>
<%

Based on your datastore and number of nodes, select a link below to install {{site.prodname}}.

>**Note**: The option, **Kubernetes API datastore, more than 50 nodes** provides scaling using [Typha daemon]({{site.baseurl}}/reference/typha/). Typha is not included for etcd because etcd already handles many clients so using Typha is redundant and not recommended.
{: .alert .alert-info}

- [Install Calico with Kubernetes API datastore, 50 nodes or less](#install-calico-with-kubernetes-api-datastore-50-nodes-or-less)
- [Install Calico with Kubernetes API datastore, more than 50 nodes](#install-calico-with-kubernetes-api-datastore-more-than-50-nodes)
- [Install Calico with etcd datastore](#install-calico-with-etcd-datastore)

##### Install Calico with Kubernetes API datastore, 50 nodes or less

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/calico.yaml -O
   ```
{% include content/pod-cidr-sed.md yaml="calico" %}
1. Customize the manifest as necessary.
1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f calico.yaml
   ```

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:Kubernetes' %}

##### Install Calico with Kubernetes API datastore, more than 50 nodes

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/calico-typha.yaml -o calico.yaml
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

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:Kubernetes' %}

##### Install Calico with etcd datastore

>**Note**: The **etcd** database is not recommended for new installs. However, it is an option if you are running {{site.prodname}} as the network plugin for both OpenStack and Kubernetes.
{: .alert .alert-info}

1. Download the {{site.prodname}} networking manifest for etcd.

   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/calico-etcd.yaml -o calico.yaml
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

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:etcd' %}

%>
{% endtabs %}

### Next steps

**Required**

- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended - Networking**

- If you are using the default BGP networking with full-mesh node-to-node peering with no encapsulation, go to [Configure BGP peering]({{site.baseurl}}/networking/bgp) to get traffic flowing between pods.
- If you are unsure about networking options, or want to implement encapsulation (overlay networking), see [Determine best networking option]({{site.baseurl}}/networking/determine-best-networking).

**Recommended - Security**

- [Secure Calico component communications]({{site.baseurl}}/security/comms/crypto-auth)
- [Secure hosts by installing Calico on hosts]({{site.baseurl}}/getting-started/bare-metal/about)
- [Secure pods with Calico network policy]({{site.baseurl}}/security/calico-network-policy)
- If you are using {{site.prodname}} with Istio service mesh, get started here: [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy)
