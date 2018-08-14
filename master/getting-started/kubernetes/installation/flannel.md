---
title: Installing Calico for policy and flannel for networking
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/kubernetes/installation/flannel'
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

1. Ensure that the Kubernetes controller manager has the following flags set:<br>
   `--cluster-cidr=10.244.0.0/16` and `--allocate-node-cidrs=true`.

   > **Tip**: If you're using kubeadm, you can pass `--pod-network-cidr=10.244.0.0/16`
   > to kubeadm to set the Kubernetes controller flags.
   {: .alert .alert-success}

1. If your cluster has RBAC enabled, issue the following command to
   configure the roles and bindings that {{site.prodname}} requires.

   ```
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/rbac.yaml
   ```
   > **Note**: You can also
   > [view the manifest in your browser](hosted/canal/rbac.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. Issue the following command to install {{site.prodname}}.

   ```bash
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/canal.yaml
   ```

   > **Note**: You can also [view the manifest in your browser](hosted/canal/canal.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enabling application layer policy](app-layer-policy) (optional).

### Installing with the etcd datastore

We strongly recommend using the Kubernetes API datastore, but if you prefer to use
etcd, complete the following steps.

1. If your cluster has RBAC enabled, issue the following command to
   configure the roles and bindings that {{site.prodname}} requires.

   ```
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/rbac-etcd.yaml
   ```
   > **Note**: You can also
   > [view the manifest in your browser](hosted/canal/rbac-etcd.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/canal-etcd.yaml \
   -O
   ```

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
