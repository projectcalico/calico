# Calico v2.5.0 Upgrade Procedure

## Why this is required

Kubernetes v1.7 introduces a new API data type called CustomResourceDefinition (CRD) which will replace the alpha ThirdPartyResource (TPR).
Calico relies on TPR to store it's config data when it uses kubernetes datastore backend. Moving forward from kubernetes v1.8, 
Kubernetes will remove the support for TPR in favor of CRD. In order to preserve the config data backed by TPR, and continue to 
work with the future Kubernetes versions, it is required to go through this migration process.
See [this blog post](https://coreos.com/blog/custom-resource-kubernetes-v17) for more information on this new data type. 

## Steps required

At a high level we need to do the following steps to make sure we have a successful upgrade.

 1. Check to make sure if you need to do the migration
 2. Backup your TPR data (Data is in TPR right now)
 3. Run the migration job (Data is copied from TPR to CRD)
 4. Verify the migration (Data is still in both TPR and CRD, Calico is still using TPR)
 5. Upgrade Calico version to `v2.5.0` (Data is still in TPR and CRD, but Calico now uses CRD backed data)
 6. Verify Calico policy and networking works as expected
 7. Delete the TPRs 

## 1. Before you begin

### 1.1 Do I need to go through this migration process?

This is only required if you meet ALL of the following criteria:

- Running Calico with Kubernetes
- Current Kubernetes version is `v1.7.x`
- Current Calico version is `v2.4.x` or lower
- Upgrading Calico to `v2.5.x`
- Calico is running with Kubernetes datastore backend (By running `calicoctl version` and making sure `Cluster Type` is `KDD`)

### 1.2 Backup your config data

We highly recommend backing up your config data before proceeding with the migration process.
We only need to backup the config backed by TPR resources; in the event the migration needs to be halted, you'll be able to restore the original data.

> Note: the migration job does not delete your old data, so your config data backed by TPR will still be there until
       deleted manually (explained in the last step of this doc).

Run the following commands to backup your config data:

> Note: use `calicoctl` version [v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) 
       and `kubectl` version [v1.7.4](https://kubernetes.io/docs/tasks/tools/install-kubectl/) to backup the data.
       
Since we will need `calicoctl` versions [v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) and [v1.5.0](https://github.com/projectcalico/calicoctl/releases/tag/v1.5.0) for this upgrade,
 we recommend downloading them both and suffixing the binaries with their respective versions (you can check the version by running `calicoctl version`)

  1.2.1. `calicoctl_v1.4 get ippools -o yaml > ippool.yaml`
  
  1.2.2. `calicoctl_v1.4 get bgppeers -o yaml > bgppeer.yaml`
  
  1.2.3. `kubectl get globalconfig --all-namespaces -o yaml > tpr-felixconfig.yaml`
  
  1.2.4. `kubectl get globalbgpconfig --all-namespaces -o yaml > tpr-bgpconfig.yaml`

> Note: you may not have some of these resources if you're using Calico in policy-only mode.

## 2. Migration process

  2.1. Create the migration kubernetes job for your cluster: `kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/master/upgrade/v2.5/manifests/upgrade-job.yaml`

  2.2. Check the job status `kubectl describe job/calico-upgrade-v2.5`

  2.3. Check the upgrade job logs `kubectl logs <upgrade-pod-name>` to make sure there aren't any errors (You can get the upgrade job's pod name from the previous command output 'Message' field)

## 3. After the migration

### 3.1 Verify that the data has been copied correctly

Make sure you have all the `IPPools`, `BGPPeers`, `GlobalFelixConfig` and `GlobalBGPConfig` resource configs you had before the upgrade:

  3.1.1. `calicoctl_v1.5 get ippools -o wide`
  
  3.1.2. `calicoctl_v1.5 get bgppeers -o wide` (This is only if you're running Calico BGP networking)
  
  3.1.3. `kubectl get globalfelixconfigs.crd.projectcalico.org -o wide`
  
  3.1.4. `kubectl get globalbgpconfigs.crd.projectcalico.org -o wide`

## 4. Upgrade calico

  4.1. (If you have RBAC enabled) Apply the updated RBAC manifest `kubectl apply -f https://docs.projectcalico.org/v2.5/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml` (this will revoke access to TPRs from calico-node)
  
  4.2. Now you can upgrade Calico version to `v2.5.0` in your kubernetes Calico DaemonSet. (Make sure you reboot your calico-node pods one at a time if calico-node `updateStrategy` is not set to `RollingUpdate`) 
  
  4.3. Verify that everything is working as expected.

## 5. Delete the old TPRs

You can now delete your TPRs by running the following command: 
`kubectl delete -f https://raw.githubusercontent.com/projectcalico/calico/master/upgrade/v2.5/manifests/tprs.yaml`
