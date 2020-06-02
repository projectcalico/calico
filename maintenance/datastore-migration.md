---
title: Migrate Calico Data from an etcdv3 Datastore to a Kubernetes Datastore
description: Migrate your cluster from using an etcdv3 datastore to a Kubernetes datastore.
canonical_url: '/maintenance/datastore-migration'
---

## Big Picture

Switch the Calico datastore from etcdv3 to Kubernetes.

## Value

In order to utilize all of Calico's newest features, Calico backed by
the kubernetes datastore is required. Migrating your data allows users
with an existing cluster set up with an etcdv3 datastore to seamlessly
transition their cluster to a Kubernetes datastore and take advantage
of new Calico functionality. For more on the advantages of using a
Kubernetes datastore over an etcd datastore, see this section of the
[Calico Datastore]({{ site.baseurl }}/getting-started/kubernetes/hardway/the-calico-datastore#using-kubernetes-as-the-datastore)
documentation.

## Before you begin...

[calicoctl]({{ site.baseurl }}/getting-started/clis/calicoctl/install) must be installed
and configured to access the current etcdv3 datastore. For more information, see the
[calicoctl configuration]({{ site.baseurl }}/getting-started/clis/calicoctl/configure/etcd)
documentation.

## How To

In order to migrate contents of the datastore, we will be using the `calicoctl migrate`
command and its accompanying subcommands. For more information, see the
[calicoctl migrate]({{ site.baseurl }}/reference/calicoctl/migrate/overview)
documentation.

1. Lock the datastore for migration. This will prevent any changes to the data from
   affecting the cluster.
   ```
   calicoctl migrate lock
   ```

2. Export the datastore contents to a file.
   ```
   calicoctl migrate export > etcd-data
   ```

3. Configure `calicoctl` to access the Kubernetes datastore. For more details, see
   the [calicoctl configuration]{{ site.baseurl }}/getting-started/clis/calicoctl/configure/kdd)
   documentation.

4. Import the datastore contents from your exported file.
   ```
   calicoctl migrate import -f etcd-data
   ```

5. Unlock the datastore. This will allow the Calico resources to affect the cluster again.
   ```
   calicoctl migrate unlock
   ```

6. Configure Calico to read from the Kubernetes datastore. This can be done by following the
   directions to install Calico with the Kubernetes datastore. See the installation instructions
   for your version of Calico in order to find and apply the relevant `calico.yaml` file.
   ```
   kubectl apply -f calico.yaml
   ```
