---
title: Downgrading Calico
redirect_from: latest/getting-started/kubernetes/upgrade/downgrade
---

Under some circumstances, you may need to perform a downgrade and return your
cluster to the previous version of {{site.prodname}}. You may need to do this
before running `calico-upgrade complete` or afterwards. If you need to downgrade 
your cluster after running `calico-upgrade complete`, you should do so as soon
as possible to avoid an outage. Any pods created after `calico-upgrade complete`
and before downgrading will lose networking.

## Downgrading a self-hosted installation

If you have upgraded {{site.prodname}} by deploying the latest manifest,
follow the steps here to downgrade.

1. Follow the steps in [Aborting the upgrade](#aborting-the-upgrade)
   before downgrading the {{site.prodname}} components.

1. Use the following commands to initiate a downgrade of the {{site.prodname}} components.

   ```
   kubectl rollout undo ds/calico-node -n kube-system
   kubectl rollout undo deployment/calico-kube-controllers -n kube-system
   ```

1. Watch the status of the downgrade as follows.

   ```
   watch kubectl get pods -n kube-system
   ```
   
   Verify that the status of all {{site.prodname}} pods indicate `Running`.

   ```
   calico-kube-controllers-6d4b9d6b5b-wlkfj   1/1       Running   0          3m
   calico-node-hvvg8                          2/2       Running   0          3m
   calico-node-vm8kh                          2/2       Running   0          3m
   calico-node-w92wk                          2/2       Running   0          3m
   ```

## Downgrading a custom installation

_Docs for this coming soon!_

## Aborting the upgrade

If you have not upgraded the {{site.prodname}} components then follow
the steps here to abort the upgrade and continue using your currently deployed
version of {{site.prodname}}.

1. Abort the upgrade by running.

   ```
   calico-upgrade abort
   ```

1. Remove any upgraded `calicoctl` instances and install the previous `calicoctl`.

> **Important**: Do not use versions of `calicoctl` v3.0+ after aborting the upgrade.
> Doing so may result in unexpected behavior and data.
{: .alert .alert-danger}
