---
title: Installing Calico for policy and networking (recommended)
canonical_url: 'https://docs.projectcalico.org/v3.7/getting-started/kubernetes/installation/calico'
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

- [Kubernetes API datastore—50 nodes or less](#installing-with-the-kubernetes-api-datastore50-nodes-or-less)

- [Kubernetes API datastore—more than 50 nodes](#installing-with-the-kubernetes-api-datastoremore-than-50-nodes)

- [etcd datastore](#installing-with-the-etcd-datastore)

### Installing with the Kubernetes API datastore—50 nodes or less

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{site.url}}/{{page.version}}/manifests/calico.yaml -O
   ```

{% include {{page.version}}/pod-cidr-sed.md yaml="calico" %}

1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f calico.yaml
   ```

1. If you wish to enforce application layer policies and secure workload-to-workload
   communications with mutual TLS authentication, continue to [Enabling application layer policy](app-layer-policy) (optional).

### Installing with the Kubernetes API datastore—more than 50 nodes

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```bash
   curl {{site.url}}/{{page.version}}/manifests/calico-typha.yaml -o calico.yaml
   ```

{% include {{page.version}}/pod-cidr-sed.md yaml="calico" %}

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
   {: .no-select-button}

   We recommend at least one replica for every 200 nodes and no more than
   20 replicas. In production, we recommend a minimum of three replicas to reduce
   the impact of rolling upgrades and failures.  The number of replicas should
   always be less than the number of nodes, otherwise rolling upgrades will stall.
   In addition, Typha only helps with scale if there are fewer Typha instances than
   there are nodes.

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

### Installing with the etcd datastore

1. Download the {{site.prodname}} networking manifest for etcd.

   ```bash
   curl {{site.url}}/{{page.version}}/manifests/calico-etcd.yaml -o calico.yaml
   ```

{% include {{page.version}}/pod-cidr-sed.md yaml="calico" %}

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
