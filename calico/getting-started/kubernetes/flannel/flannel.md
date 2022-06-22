---
title: Install Calico for policy and flannel (aka Canal) for networking
description: If you use flannel for networking, you can install Calico network policy to secure cluster communications.
canonical_url: '/getting-started/kubernetes/flannel'
---

### Before you begin

> **Note**: Calico includes native VXLAN capabilities without the need for flannel. If you're planning on using flannel for VXLAN, we recommend instead installing Calico using IP-in-IP or VXLAN mode. See how to [determine the best networking option]({{site.baseurl}}/networking/determine-best-networking) for your cluster.
> If you're already using flannel for networking, you can [migrate your existing clusters to Calico networking]({{site.baseurl}}/getting-started/kubernetes/flannel/migration-from-flannel).
{: .alert .alert-info}

Ensure that you have a Kubernetes cluster that meets the
{{site.prodname}} [system requirements](../requirements). If you don't,
follow the steps in {% include open-new-window.html text='Installing kubeadm' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/' %}.

### Installing {{site.prodname}} for policy and flannel (aka Canal) for networking

#### Selecting a datastore type

The procedure differs according to your datastore type. Refer to the section that matches your type.

- [Kubernetes API datastore](#installing-with-the-kubernetes-api-datastore-recommended) (recommended)

- [etcd datastore](#installing-with-the-etcd-datastore)

#### Installing with the Kubernetes API datastore (recommended)

1. Ensure that the Kubernetes controller manager has the following flags
   set: <br>
   `--cluster-cidr=<your-pod-cidr>` and `--allocate-node-cidrs=true`.

   > **Tip**: On kubeadm, you can pass `--pod-network-cidr=<your-pod-cidr>`
   > to kubeadm to set both Kubernetes controller flags.
   {: .alert .alert-success}

1. Download the flannel networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/canal.yaml -O
   ```

{% include content/pod-cidr-sed.md yaml="canal" %}

1. Issue the following command to install {{site.prodname}}.

   ```bash
   kubectl apply -f canal.yaml
   ```

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy) (optional).

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Host-local,CNI:Calico,Overlay:VXLAN,Routing:Static,Datastore:Kubernetes' %}

#### Installing with the etcd datastore

We strongly recommend using the Kubernetes API datastore, but if you prefer to use
etcd, complete the following steps.

1. Download the {{site.prodname}} networking manifest.

   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/canal-etcd.yaml -O
   ```

{% include content/pod-cidr-sed.md yaml="canal-etcd" %}

1. In the `ConfigMap` named `calico-config`, set the value of
   `etcd_endpoints` to the IP address and port of your etcd server.

   > **Tip**: You can specify more than one using commas as delimiters.
   {: .alert .alert-success}

1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f canal-etcd.yaml
   ```

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy) (optional).

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Host-local,CNI:Calico,Overlay:VXLAN,Routing:Static,Datastore:etcd' %}

