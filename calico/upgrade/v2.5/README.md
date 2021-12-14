# Upgrading to Calico v2.5.0 or later with Kubernetes datastore

## Why this is required

Kubernetes v1.7 introduces a new CustomResourceDefinition (CRD) API resource. The CRD resource will replace the alpha ThirdPartyResource (TPR). Support for TPR will end in Kubernetes v1.8. 

If you are using the Kubernetes datastore with Calico v2.4.x or earlier, you must migrate Calico's configuration data from TPR to CRD before upgrading to Calico v2.5.0 or later. If you fail to migrate the data before upgrading calico/node, calico/node will not come up after the upgrade and your connectivity will be affected. 

To read more about the new CRD resource, see [TPR Is Dead! Kubernetes 1.7 Turns to CRD](https://coreos.com/blog/custom-resource-kubernetes-v17). 

## Steps required

At a high level you must complete the following steps to ensure a successful upgrade.

 1. [Check to make sure you need to do the migration.](#1-before-you-begin)
 2. [Back up your TPR data.](#12-back-up-your-configuration-data) Data is in TPR.
 3. [Copy the data from TPR to CRD.](#2-migration-process) Data is in both TPR and CRD.
 4. [Verify the migration.](#3-verify-that-the-data-has-been-copied-correctly) Data is still in both TPR and CRD. Calico is still using TPR.
 5. [Upgrade Calico.](#4-upgrade-calico) Data is still in TPR and CRD, but Calico now uses CRD.
 6. Verify Calico policy and networking works as expected.
 7. [Delete the TPRs.](#5-delete-the-old-tprs)

## 1. Before you begin

### 1.1 Do I need to go through this migration process?

This is only required if you meet ALL of the following criteria:

- Running Calico with Kubernetes datastore (**Tip**: If `calicoctl version` returns a `Cluster Type` of `KDD`, you are using the Kubernetes datastore.)
- Current Kubernetes version is `v1.7.x`
- Current Calico version is `v2.4.x` or earlier
- Upgrading Calico to `v2.5.x` or later

### 1.2 Back up your configuration data

We highly recommend backing up your configuration data before proceeding with the migration process.
We only need to back up the configuration data stored as TPR resources. In the event the migration needs to be halted, this will allow you to restore the original data.

> **Note**: the migration job does not delete your old data, so your configuration data stored in TPR will still be there until [deleted manually](#5-delete-the-old-tprs).

> **Note**: use [`calicoctl` version v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) and [`kubectl` version v1.7.4](https://kubernetes.io/docs/tasks/tools/install-kubectl/) to back up the data. Since we will need [`calicoctl` version v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) and [v1.5.0](https://github.com/projectcalico/calicoctl/releases/tag/v1.5.0) for this upgrade,
 we recommend downloading them both and suffixing the binaries with their respective versions. You can check the version by running `calicoctl version`.
 
 Run the following commands in sequence to back up your configuration data:

  1.2.1. `calicoctl_v1.4 get ippools -o yaml > ippool.yaml`
  
  1.2.2. `calicoctl_v1.4 get bgppeers -o yaml > bgppeer.yaml`
  
  1.2.3. `kubectl get globalconfig --all-namespaces -o yaml > tpr-felixconfig.yaml`
  
  1.2.4. `kubectl get globalbgpconfig --all-namespaces -o yaml > tpr-bgpconfig.yaml`

> **Note**: you may not have some of these resources if you're using Calico in policy-only mode.

## 2. Migration process

  2.1. Create the migration kubernetes job for your cluster: `kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/master/upgrade/v2.5/manifests/upgrade-job.yaml`.

  2.2. Check the job status `kubectl describe job/calico-upgrade-v2.5`.

  2.3. Check the upgrade job logs `kubectl logs <upgrade-pod-name>` to make sure there aren't any errors. (You can get the upgrade job's pod name from the previous command output `Message` field.)

## 3. Verify that the data has been copied correctly

Make sure you have all the `IPPools`, `BGPPeers`, `GlobalFelixConfig`, and `GlobalBGPConfig` resource configs you had before the migration:

  3.1. `calicoctl_v1.5 get ippools -o wide`
  
  3.2. `calicoctl_v1.5 get bgppeers -o wide` (This is only if you're running Calico BGP networking.)
  
  3.3. `kubectl get globalfelixconfigs.crd.projectcalico.org -o wide`
  
  3.4. `kubectl get globalbgpconfigs.crd.projectcalico.org -o wide`

## 4. Upgrade calico

  > **Note**: If you are updating a [Canal](https://github.com/projectcalico/canal/tree/master/k8s-install)
  deployment do not use the RBAC manifest in the following step, instead use the
  appropriate [Canal RBAC manifest](https://github.com/projectcalico/canal/blob/master/k8s-install/1.7/rbac.yaml).

  4.1. If you have RBAC enabled, apply the updated RBAC manifest `kubectl apply -f https://docs.projectcalico.org/v2.5/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml`. (This will revoke access to TPRs from calico-node.)
  
  4.2. Now you can upgrade the calico/node and calico/cni images in your Kubernetes Calico DaemonSet. (Make sure you reboot your calico-node pods one at a time if calico-node `updateStrategy` is not set to `RollingUpdate`.)
  
  4.3. Verify that everything is working as expected.

## 5. Delete the old TPRs

You can now delete your TPRs by running the following command: 
`kubectl delete -f https://raw.githubusercontent.com/projectcalico/calico/master/upgrade/v2.5/manifests/tprs.yaml`
