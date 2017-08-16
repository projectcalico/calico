# Calico v2.5.0 Upgrade Procedure

## Why this is required

Kubernetes v1.7 introduced a new API data type called CustomResourceDefinition (CRD) which will replace ThirdPartyResources (TPR).
Calico relies on TPR to store it's config data when it uses kubernetes datastore backend. Moving forward from kubernetes v1.8, 
Kubernetes will remove the support for TPR in favor of CRD. In order to preserve the config data backed by TPR, and continue to 
work with the future Kubernetes versions, it is required to go through this migration process.
See [this blog post](https://coreos.com/blog/custom-resource-kubernetes-v17) for more information on this new data type. 

## Steps required

At a higher level we need to do the following steps to make sure we have a successful upgrade.

1. Check to make sure if you need to do the migration
2. Backup your TPR data (Data is in TPR right now)
3. Run the migration job (Data is copied from TPR to CRD)
4. Verify the migration (Data is still in both TPR and CRD, Calico is still using TPR)
5. Upgrade Calico version to `v2.5.0` (Data is still in TPR and CRD, but Calico now uses CRD backed data)
6. Verify Calico policy and networking works as expected
7. Delete the TPRs 

## Before you begin

### Do I need to go through this migration process?

This is only required if you meet ALL of the following criteria:

- Running Calico with Kubernetes
- Current Kubernetes version is v1.7.x
- Current Calico version is v2.4.x or lower
- Upgrading Calico to v2.5.x
- Calico is running with Kubernetes datastore backend

### Backup your config data

We highly recommend backing up your config data before proceeding with the migration process.
We only need to backup the config backed by TPR resources; in the event the migration needs to be halted, you'll be able to restore the original data.

> Note: the migration job does not delete your old data, so your config data backed by TPR will still be there until
       deleted manually (explained in the last step of this doc).

Run the following commands to backup your config data:

> Note: use calicoctl version [v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) 
       and kubectl version [v1.7.3](https://kubernetes.io/docs/tasks/tools/install-kubectl/) to backup the data.

1. `calicoctl get ippool -o yaml > ippool.yaml`
2. `calicoctl get globalbgppeer -o yaml > bgppeer.yaml`
3. `kubectl get globalconfig --all-namespaces -o yaml > tpr-felixconfig.yaml`
4. `kubectl get globalbgpconfig --all-namespaces -o yaml > tpr-bgpconfig.yaml`



## Migration process

1. Clone this repo: `git clone https://github.com/projectcalico/calico`
2. Apply the migration kubernetes job manifest to your cluster: `kubectl apply -f ./calico/upgrade/v2.5/manifests/upgrade-job.yaml`
3. Check the job status `kubectl describe job/calico-upgrade-v2.5`
4. Check the upgrade job logs `kubectl logs <upgrade-pod-name>` (You can get the upgrade job's pod name from the previous command output 'Message' field)

## After the migration

### Verify that the data has been copied fine

Make sure you have all the `IPPools`, `BGPPeers`, `GlobalFelixConfig` and `GlobalBGPConfig` resource configs you had before the upgrade:

1. `calicoctl get ippools -o wide`
2. `calicoctl get bgppeer -o wide` (This is only if you're running Calico BGP networking)
3. `kubectl get globalfelixconfig -o wide`
4. `kubectl get globalbgpconfig -o wide`

## Upgrade calico

Now you can upgrade Calico version to `v2.5.0` in your kubernetes Calico DaemonSet with rolling update. 

### Delete the old TPRs

1. List all the Calico TPRs: `kubectl get thirdpartyresource`
2. Delete the Calico TPRs: `kubectl delete <TPR-name>` (The Calico TPRs you get from the previous command output, make sure you only delete the ones with `projectcalico.org` in the name)
