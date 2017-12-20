---
title: Upgrading Calico 
no_canonical: true
---
  

## About upgrading {{site.prodname}}

Once you have migrated the {{site.prodname}} data to the etcdv3 server, you can upgrade 
{{site.prodname}}. The procedure varies according to how you originally installed {{site.prodname}}.

- [Upgrading a self-hosted installation](#upgrading-a-self-hosted-installation)

- [Upgrading a custom installation](#upgrading-a-custom-installation)

Once you have upgraded {{site.prodname}}, you can [complete the upgrade](#completing-the-upgrade)


## Upgrading a self-hosted installation

1. [Refer to the v3.0 documentation and obtain the manifest that matches your installation
   method.](https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/)

1. Use the following command to initiate a rolling update, after replacing `<v3-manifest>` with
   the name of the manifest file obtained in the previous step.

   ```
   kubectl apply -f <v3-manifest>
   ```
1. Watch the status of the upgrade as follows.

   ```
   watch kubectl get pods -n kube-system
   ```
   
   Verify that the status of all {{site.prodname}} pods indicate `Running`.

   ```
   calico-kube-controllers-6d4b9d6b5b-wlkfj   1/1       Running   0          3m
   calico-node-hvvg8                          1/2       Running   0          3m
   calico-node-vm8kh                          1/2       Running   0          3m
   calico-node-w92wk                          1/2       Running   0          3m
   ```

   > **Note**: The {{site.noderunning}} pods will report `1/2` in the `READY` column, as shown.
   {: .alert .alert-info}
   
1. After waiting some time and ensuring that the upgrade succeeded and no problems ensued,
   continue to [Completing the upgrade](#completing-the-upgrade).

   If an error occurs during the upgrade, refer to [Downgrading Calico](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).


## Upgrading a custom installation

_Docs for this coming soon!_

## Completing the upgrade

1. When all of your calico/node instances and orchestrator plugins are running v3.0.x 
   then complete the upgrade by running `calico-upgrade complete`. After this, you can
   once again schedule pods and make changes to configuration and policy. 

   If you experience errors after running `calico-upgrade complete`, such as an inability
   to schedule pods, [downgrade Calico as soon as possible](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).
   
1. Remove any existing `calicoctl` instances and install the new `calicoctl`.

> **Important**: Do not use older versions of `calicoctl` after the migration and upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}
