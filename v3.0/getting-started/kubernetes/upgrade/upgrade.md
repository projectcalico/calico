---
title: Upgrading Calico 
canonical_url: https://docs.projectcalico.org/v3.2/getting-started/kubernetes/upgrade/upgrade
---



## About upgrading {{site.prodname}}

The upgrade procedure varies according to how you originally installed {{site.prodname}}
and your datastore type.

- [Upgrading a self-hosted installation that uses the Kubernetes API datastore](#upgrading-a-self-hosted-installation-that-uses-the-kubernetes-api-datastore)

- [Upgrading a self-hosted installation that connects directly to an etcd datastore](#upgrading-a-self-hosted-installation-that-uses-the-etcd-datastore)

> **Important**: Do not use older versions of `calicoctl` after the upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}


## Upgrading a self-hosted installation that uses the Kubernetes API datastore
   
1. If your configuration uses RBAC, use the following command to create the roles 
   and role bindings for {{site.prodname}}'s components:

   ```
   kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
   ```
   > **Note**: You can also 
   > [view the YAML in your browser]({{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. [Refer to the Kubernetes datastore hosted installation documentation and 
   obtain the manifest needed for your configuration.](https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/kubernetes-datastore/)

1. Use the following command to initiate a rolling update, after replacing 
   `<v3-manifest>` with the name of the manifest file obtained in the previous step.

   ```
   kubectl apply -f <v3-manifest>
   ```
   
1. Watch the status of the upgrade as follows.

   ```
   watch kubectl get pods -n kube-system
   ```
   
   Verify that the status of all {{site.prodname}} pods indicate `Running`.

   ```
   calico-node-hvvg8                          2/2       Running   0          3m
   calico-node-vm8kh                          2/2       Running   0          3m
   calico-node-w92wk                          2/2       Running   0          3m
   ```

1. Use the following command to confirm that {{site.noderunning}} has upgraded to v3.0.x.

   ```
   kubectl exec -n kube-system calico-node-hvvg8 versions
   ```
   
   It should return `v3.0.x`.
   
   > **Note**: If an error occurs during the upgrade, refer to 
   > [Downgrading Calico](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).
   {: .alert .alert-info}
   
1. Remove any existing `calicoctl` instances and install the new `calicoctl`.

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.


## Upgrading a self-hosted installation that uses the etcd datastore

1. [Refer to the v3.0 documentation and obtain the manifest that matches your installation
   method.](https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/)

1. Use the following command to initiate a rolling update, after replacing 
   `<v3-manifest>` with the name of the manifest file obtained in the previous step.

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

   > **Tip**: The {{site.noderunning}} pods will report `1/2` in the `READY` column, as shown.
   {: .alert .alert-success}

   > **Note**: If an error occurs during the upgrade, refer to 
   > [Downgrading Calico](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).
   {: .alert .alert-info}
   
1. Use the following command to confirm that {{site.noderunning}} has upgraded to v3.0.x.

   ```
   kubectl exec -n kube-system calico-node-hvvg8 versions
   ```
   
   It should return `v3.0.x`.
   
1. We recommend waiting for some time and really ensuring that the upgrade succeeded 
   and no problems ensued before completing the upgrade by running 
   `calico-upgrade complete`. After this, you can once again schedule pods and 
   make changes to configuration and policy. 

   > **Important**: If you experience errors after running `calico-upgrade complete`, 
   > such as an inability to schedule pods, [downgrade Calico as soon as possible](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).
   {: .alert .alert-danger}
   
1. Remove any existing `calicoctl` instances and install the new `calicoctl`.

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.



