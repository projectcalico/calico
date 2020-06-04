---
title: Migrate Calico data from an etcdv3 datastore to a Kubernetes datastore
description: Migrate your cluster from using an etcdv3 datastore to a Kubernetes datastore.
canonical_url: '/maintenance/datastore-migration'
---

## Big picture

Switch your {{site.prodname}} datastore from etcdv3 to Kubernetes.

## Value

To utilize all of {{site.prodname}}'s newest features, Kubernetes datastore
is required. We provide a seamless way to migrate your data from an existing
cluster with an etcdv3 datastore to a Kubernetes datastore. For the
advantages of using a Kubernetes datastore over an etcd datastore, see
[{{site.prodname}} Datastore]({{ site.baseurl }}/getting-started/kubernetes/hardway/the-calico-datastore#using-kubernetes-as-the-datastore)
documentation.

## Before you begin...

[calicoctl must be installed and configured]({{ site.baseurl }}/getting-started/clis/calicoctl/install)

## How To

To migrate contents of the datastore, we will be using the `calicoctl datastore migrate`
command and subcommands. For more information, see the
[calicoctl datastore migrate]({{ site.baseurl }}/reference/calicoctl/migrate/overview)
documentation.

1. Lock the etcd datastore for migration. This prevents any changes to the data from
   affecting the cluster.
   ```
   calicoctl datastore migrate lock
   ```

1. Export the datastore contents to a file.
   ```
   calicoctl datastore migrate export > etcd-data
   ```

1. Configure `calicoctl` to access the
   [Kubernetes datastore]({{ site.baseurl }}/getting-started/clis/calicoctl/configure/kdd).

1. Import the datastore contents from your exported file.
   ```
   calicoctl datastore migrate import -f etcd-data
   ```

1. Configure {{site.prodname}} to read from the Kubernetes datastore. Follow the
   directions to install {{site.prodname}} with the Kubernetes datastore. The
   installation instructions contain the relevant version of the
   `calico.yaml` file to apply.
   ```
   kubectl apply -f calico.yaml
   ```
   >**Note**: If upgrading to an operator installed version of {{site.prodname}},
   there will not be a `calico.yaml` file to apply. Follow the operator installation
   instructions instead.
   {: .alert .alert-info}

1. Unlock the datastore. This allows the {{site.prodname}} resources to affect the cluster again.
   ```
   calicoctl datastore migrate unlock
   ```

