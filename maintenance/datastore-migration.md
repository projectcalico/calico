---
title: Migrate Calico data from an etcdv3 datastore to a Kubernetes datastore
description: Migrate your cluster from using an etcdv3 datastore to a Kubernetes datastore.
canonical_url: '/maintenance/datastore-migration'
---

## Big picture

Switch your {{site.prodname}} datastore from etcdv3 to Kubernetes on a live cluster.

## Value

Using Kubernetes as your datastore provides a number of benefits over using etcdv3
directly, including fewer components and better support for role based access
control. For most users, using the Kubernetes data store will provide a better
experience. We provide a seamless way to migrate your data from an existing
cluster with an etcdv3 datastore to a Kubernetes datastore. For the
complete set of advantages of using a Kubernetes datastore over an etcd datastore, see
[{{site.prodname}} Datastore]({{ site.baseurl }}/getting-started/kubernetes/hardway/the-calico-datastore#using-kubernetes-as-the-datastore)
documentation.

## Before you begin...

[calicoctl must be installed and configured]({{ site.baseurl }}/getting-started/clis/calicoctl/install)

## How To

To migrate contents of the datastore, we will be using the `calicoctl datastore migrate`
command and subcommands. For more information, see the
[calicoctl datastore migrate]({{ site.baseurl }}/reference/calicoctl/datastore/migrate/overview)
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

1. Verify that the datastore was properly imported. This can be accomplished by using
   `calicoctl` to query for any {{site.prodname}} resources that exist in the etcd
   datastore (e.g. networkpolicy).
   ```
   calicoctl get networkpolicy 
   ```

1. Configure {{site.prodname}} to read from the Kubernetes datastore. Follow the
   directions to install {{site.prodname}} with the Kubernetes datastore. The
   installation instructions contain the relevant version of the
   `calico.yaml` file to apply.
   ```
   kubectl apply -f calico.yaml
   ```

1. Unlock the datastore. This allows the {{site.prodname}} resources to affect the cluster again.
   ```
   calicoctl datastore migrate unlock
   ```

## Roll back the datastore migration.

Rolling back the datastore migration can only be done if the original etcd datastore still exists.
The following steps delete the {{site.prodname}} resources imported into the Kubernetes datastore
and configure the cluster to once again read from the original etcd datastore.

1. Lock the Kubernetes datastore.
   ```
   calicoctl datastore migrate lock
   ```

1. Delete all of the {{site.prodname}} CRDs. This will remove all of the data imported into
   the Kubernetes datastore.
   ```
   kubectl delete $(kubectl get crds -o name | grep projectcalico.org)
   ```

1. Configure {{site.prodname}} to read from the etcd datastore. Follow the
   directions to install {{site.prodname}} with the etcd datastore. The
   installation instructions contain the relevant version of the
   `calico.yaml` file to apply.
   ```
   kubectl apply -f calico.yaml
   ```

1. Configure `calicoctl` to access the
   [etcd datastore]({{ site.baseurl }}/getting-started/clis/calicoctl/configure/etcd).

1. Unlock the etcd datastore. This allows the {{site.prodname}} resources to affect the cluster again.
   ```
   calicoctl dtastore migrate unlock
   ```
