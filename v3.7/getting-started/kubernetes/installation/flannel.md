---
title: Installing Calico for policy and flannel for networking
redirect_from: latest/getting-started/kubernetes/installation/flannel
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/installation/flannel'
---

## Before you begin

Ensure that you have a Kubernetes cluster that meets the
{{site.prodname}} [system requirements](../requirements). If you don't,
follow the steps in [Using kubeadm to create a cluster](http://kubernetes.io/docs/getting-started-guides/kubeadm/).

## Installing {{site.prodname}} for policy and flannel for networking

### Selecting a datastore type

The procedure differs according to your datastore type. Refer to the
section that matches your type.

- [Kubernetes API datastore](#installing-with-the-kubernetes-api-datastore-recommended) (recommended)

- [etcd datastore](#installing-with-the-etcd-datastore)

### Installing with the Kubernetes API datastore (recommended)

1. Ensure that the Kubernetes controller manager has the following flags
   set: <br>
   `--cluster-cidr=<your-pod-cidr>` and `--allocate-node-cidrs=true`.

   > **Tip**: On kubeadm, you can pass `--pod-network-cidr=<your-pod-cidr>`
   > to kubeadm to set both Kubernetes controller flags.
   {: .alert .alert-success}

1. Download the flannel networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{site.url}}/{{page.version}}/manifests/canal.yaml -O
   ```

{% include {{page.version}}/pod-cidr-sed.md yaml="canal" %}

1. Issue the following command to install {{site.prodname}}.

   ```bash
   kubectl apply -f canal.yaml
   ```

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enabling application layer policy](app-layer-policy) (optional).

### Installing with the etcd datastore

We strongly recommend using the Kubernetes API datastore, but if you prefer to use
etcd, complete the following steps.

1. Download the {{site.prodname}} networking manifest.

   ```bash
   curl {{site.url}}/{{page.version}}/manifests/canal-etcd.yaml -O
   ```

{% include {{page.version}}/pod-cidr-sed.md yaml="canal-etcd" %}

1. In the `ConfigMap` named `calico-config`, set the value of
   `etcd_endpoints` to the IP address and port of your etcd server.

   > **Tip**: You can specify more than one using commas as delimiters.
   {: .alert .alert-success}

1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f canal-etcd.yaml
   ```

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enabling application layer policy](app-layer-policy) (optional).
