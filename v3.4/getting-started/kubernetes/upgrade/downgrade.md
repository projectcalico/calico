---
title: Downgrading Calico
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/kubernetes/upgrade/downgrade'
---

## About downgrading {{site.prodname}}

Under some circumstances, you may need to perform a downgrade and return your
cluster to the previous version of {{site.prodname}}. If you need to downgrade
you should do so as soon as possible to avoid an outage.

> **Note**: After downgrading or aborting the migration it is necessary
> to delete the previously migrated
> [etcd](delete#deleting-calico-data-from-etcdv2-after-a-successful-migration-and-upgrade)
> or [Kubernetes API](delete#deleting-calico-data-from-the-kubernetes-api-datastore-after-a-downgrade)
> data before re-running the migration.
{: .alert .alert-info}

The downgrade procedure varies according to how you originally installed
{{site.prodname}} and your datastore type.

- Follow the steps to [Downgrade a self-hosted installation that uses the etcd
  datastore](#downgrading-a-self-hosted-installation-that-uses-the-etcd-datastore)
  when migration has been done and the {{site.prodname}} components have been
  upgraded.
  > **Important**: Any pods created after `calico-upgrade complete` and
  > before downgrading will lose networking.
  {: .alert .alert-danger}

- To [Downgrade a self-hosted installation that uses the
  Kubernetes API datastore](#downgrading-a-self-hosted-installation-that-uses-the-kubernetes-api-datastore)
  follow these steps.

## Downgrading a self-hosted installation that uses the etcd datastore

If you have upgraded {{site.prodname}} by deploying the latest manifest,
follow the steps here to downgrade.

1. Remove any upgraded `calicoctl` instances and install the previous `calicoctl`.

1. Use the following command to re-enable the previous {{site.prodname}} components.

   ```
   calico-upgrade abort
   ```
   
   > **Important**: Do not use versions of `calicoctl` v3.x after aborting the upgrade.
   > Doing so may result in unexpected behavior and data.
   {: .alert .alert-danger}

1. Use the following commands to initiate a downgrade of the {{site.prodname}} components.

   ```
   kubectl rollout undo ds/calico-node -n kube-system
   kubectl rollout undo deployment/calico-kube-controllers -n kube-system
   ```

1. Watch the status of the downgrade as follows. When it reports complete and
   successful, {{site.prodname}} is downgraded to the previous version.

   ```
   kubectl rollout status deployment/calico-kube-controllers -n kube-system
   kubectl rollout status ds/calico-node -n kube-system
   ```

## Downgrading a self-hosted installation that uses the Kubernetes API datastore

1. Use the following commands to initiate a downgrade of the {{site.prodname}} components.

   ```
   kubectl rollout undo ds/calico-node -n kube-system
   ```

1. Watch the status of the downgrade as follows. When it reports complete and
   a successful, {{site.prodname}} is downgraded to the previous version.

   ```
   kubectl rollout status ds/calico-node -n kube-system
   ```
