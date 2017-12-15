---
title: Upgrading Calico components
no_canonical: true
---
  

1. Upgrade each component to the latest v3.0.x release.

   - If you are running with a full node-to-node mesh then you will need to update one 
     node at a time to minimize the effect of any route flaps.
     
   - If you are running with one or more route reflectors or using Calico for policy only 
     then you should be able to do a rolling update with multiple nodes upgrading at 
     the same time.

   > **Note**: While Calico installs typically require just a single command and YAML file,
   > we recommend upgrading components one at a time. 
   {: .alert .alert-info}

1. [Visit the v3.0 installation documentation to locate and download the v3.0 manifest appropriate to your configuration](/master/getting-started/kubernetes/installation/hosted/).

1. Copy the `calico/kube-controllers` deployment section and paste it into a new file called `new-controllers.yaml`.

1. Use the following command to upgrade the `calico/kube-controllers`.

   ```
   kubectl apply -f new-controllers.yaml
   ```

   > **Note**: The deployment must use `.spec.strategy.type==Recreate` to
   > ensure that at most one instance of the controller is running at a time.
   {: .alert .alert-info}

1. Copy the Calico DaemonSet section and paste it into a new file called `calico-node.yaml`.

1. Use the following command to upgrade `calico/node`.

   ```
   kubectl apply -f new-controllers.yaml
   ```

1. Perform the following steps on each node one at a time.

1. First make the node unschedulable:

   ```
   kubectl cordon node-01
   ```

1. Delete the calico-node pod running on the cordoned node and wait for the
   DaemonSet controller to deploy a replacement.

   ```
   kubectl delete pod -n kube-system calico-node-ajzy6e3t
   ```

1. Once the new calico-node Pod has started, make the node schedulable again.

   ```
   kubectl uncordon node-01
`  ```


   > **Note**: You may want to pre-fetch the new Docker image to ensure the new
   > node image is started within BIRD's graceful restart period of 90 seconds.
   {: .alert .alert-info}

     
1. When all of your calico/node instances and orchestrator plugins are running v3.0.x 
   then complete the upgrade by running `calico-upgrade complete`. After this, you can
   once again add endpoints. 
   
1. Remove any existing `calicoctl` instances and install the new `calicoctl`.

> **Important**: Do not use older versions of `calicoctl` after the migration and upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}
