---
title: Installing Calico for policy and networking (recommended)
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/kubernetes/installation/calico'
---

## Before you begin

Ensure that you have a Kubernetes cluster that meets the
{{site.prodname}} [system requirements](../requirements). If you don't,
follow the steps in [Using kubeadm to create a cluster](http://kubernetes.io/docs/getting-started-guides/kubeadm/).

## Installing {{site.prodname}} for policy and networking

### Selecting your datastore type and number of nodes

The procedure differs according to the type of datastore you want {{site.prodname}}
to use and the number of nodes. Refer to the section that matches your desired
datastore type and number of nodes.

- [etcd datastore](#installing-with-the-etcd-datastore)

- [Kubernetes API datastore—50 nodes or less](#installing-with-the-kubernetes-api-datastore50-nodes-or-less) (beta)

- [Kubernetes API datastore—more than 50 nodes](#installing-with-the-kubernetes-api-datastoremore-than-50-nodes) (beta)

> **Note**: {{site.prodname}} networking with the Kubernetes API datastore
> is beta because it does not yet support {{site.prodname}} IPAM. It uses
> `host-local` IPAM with Kubernetes pod CIDR assignments instead.
{: .alert .alert-info}

### Installing with the etcd datastore

1. If your cluster has RBAC enabled, issue the following command to
   configure the roles and bindings that {{site.prodname}} requires.

   ```
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/rbac.yaml
   ```
   > **Note**: You can also
   > [view the manifest in your browser](rbac.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. Download the {{site.prodname}} networking manifest for etcd.

   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/calico.yaml \
   -O
   ```

1. In the `ConfigMap` named `calico-config`, set the value of
   `etcd_endpoints` to the IP address and port of your etcd server.

   > **Tip**: You can specify more than one using commas as delimiters.
   {: .alert .alert-success}

1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f calico.yaml
   ```

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enabling application layer policy](app-layer-policy) (optional).

### Installing with the Kubernetes API datastore—50 nodes or less

1. Ensure that the Kubernetes controller manager has the following flags
   set: <br>
   `--cluster-cidr=192.168.0.0/16` and `--allocate-node-cidrs=true`.

   > **Tip**: On kubeadm, you can pass `--pod-network-cidr=192.168.0.0/16`
   > to kubeadm to set both Kubernetes controller flags.
   {: .alert .alert-success}

1. If your cluster has RBAC enabled, issue the following command to
   configure the roles and bindings that {{site.prodname}} requires.

   ```
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
   ```
   > **Note**: You can also
   > [view the manifest in your browser](hosted/rbac-kdd.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. Issue the following command to install {{site.prodname}}.

   ```bash
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml
   ```

   > **Note**: You can also [view the manifest in your browser](hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enabling application layer policy](app-layer-policy) (optional).

### Installing with the Kubernetes API datastore—more than 50 nodes

1. Ensure that the Kubernetes controller manager has the following flags set:<br>
   `--cluster-cidr=192.168.0.0/16` and `--allocate-node-cidrs=true`.

   > **Tip**: On kubeadm, you can pass `--pod-network-cidr=192.168.0.0/16`
   > to kubeadm to set both Kubernetes controller flags.
   {: .alert .alert-success}

1. If your cluster has RBAC enabled, issue the following command to
   configure the roles and bindings that {{site.prodname}} requires.

   ```
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
   ```
   > **Note**: You can also
   > [view the manifest in your browser](hosted/rbac-kdd.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml \
   -O
   ```

1. In the `ConfigMap` named `calico-config`, locate the `typha_service_name`,
   delete the `none` value, and replace it with `calico-typha`.

1. Modify the replica count in the`Deployment` named `calico-typha`
   to the desired number of replicas.

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

   We recommend at least one replica for every 200 nodes and no more than
   20 replicas. In production, we recommend a minimum of three replicas to reduce
   the impact of rolling upgrades and failures.

   > **Warning**: If you set `typha_service_name` without increasing the replica
   > count from its default of `0` Felix will try to connect to Typha, find no
   > Typha instances to connect to, and fail to start.
   {: .alert .alert-danger}

1. Apply the manifest.

   ```bash
   kubectl apply -f calico.yaml
   ```

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enabling application layer policy](app-layer-policy) (optional).
