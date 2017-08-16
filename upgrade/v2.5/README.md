# Calico v2.5.0 Upgrade Procedure

## Why is this required

Kubernetes v1.7 introduced a new API data type called CustomResourceDefinition (CRD) which will replace ThirdPartyResources (TPR).
Calico relies on TPR to store it's config data when it uses kubernetes datastore backend. Moving forward from kubernetes v1.8, 
Kubernetes will remove the support for TPR in favor of CRD. In order to preserve the config data backed by TPR, and continue to 
work with the future Kubernetes versions, it is required to go through this migration process.
See [this blog post](https://coreos.com/blog/custom-resource-kubernetes-v17) for more information on this new data type. 



## Before you begin

### Do I need to go through this migration process?

This is only required if you meet ALL of the following criteria:

- Running Calico with Kubernetes v1.7.x
- Current Calico version v2.4.x or lower
- Upgrading Calico to v2.5.x
- Calico is running with Kubernetes datastore backend

### Backup your config data

We highly recommend backing up your config data before proceeding with the migration process.
We only need to backup the data that is backed by TPR, so in case if something goes wrong with the migration, you have a backup.
Note: migration job does not delete your old data, so your config data backed by TPR will still be there until
      deleted manually (explained in the last step of this doc)

Run the following commands to backup your config data:
Note: use calicoctl version [v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) 
      and kubectl version [v1.7.3](https://kubernetes.io/docs/tasks/tools/install-kubectl/)to backup the data.

1. `calicoctl get ippool -o yaml > ippool.yaml`
2. `calicoctl get globalbgppeer -o yaml > bgppeer.yaml`
3. `kubectl get globalconfig --all-namespaces -o yaml > tpr-felixconfig.yaml`
4. `kubectl get globalbgpconfig --all-namespaces -o yaml > tpr-bgpconfig.yaml`



## Upgrade process

## After the upgrade

### Verify that everything is working

### Delete the old TPRs