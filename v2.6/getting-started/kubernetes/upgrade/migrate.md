---
title: Migrating from TPR to CRD
redirect_from: latest/getting-started/kubernetes/upgrade/migrate
---

## Why this is required

Kubernetes v1.7 introduces a new CustomResourceDefinition (CRD) API resource. 
The CRD resource will replace the alpha ThirdPartyResource (TPR). Support for 
TPR will end in Kubernetes v1.8. 

If you are using the Kubernetes API datastore with a version of {{side.prodname}} earlier
than v2.5.0, you must migrate {{side.prodname}}'s configuration data from TPR to CRD before 
upgrading. 

> **Important**: If you fail to migrate the data before upgrading `calico/node`, 
> `calico/node` will not come up after the upgrade and your connectivity 
> will be affected.
{: .alert .alert-danger}

To read more about the new CRD resource, refer to [TPR Is Dead! Kubernetes 1.7 Turns to CRD](https://coreos.com/blog/custom-resource-kubernetes-v17). 

## Steps required

At a high level you must complete the following steps.

1. [Check to make sure you need to do the migration.](#do-i-need-to-go-through-this-migration-process)
1. [Ensure that you meet the prerequisites.](#prerequisite)
1. [Back up your TPR data.](#back-up-your-configuration-data) Data is in TPR.
1. [Copy the data from TPR to CRD.](#migration-process) Data is in both TPR and CRD.
1. [Verify that the data has been copied correctly.](#verify-that-the-data-has-been-copied-correctly) Data 
   is still in both TPR and CRD. {{side.prodname}} is still using TPR.
1. [Apply updated RBAC manifest.](#apply-updated-RBAC-manifest) If RBAC is enabled.

## Before you begin

### Do I need to go through this migration process?

This is only required if you meet ALL of the following criteria:

- Current {{side.prodname}} version is earlier than v2.5.0
- Running {{side.prodname}} with the Kubernetes API datastore 

> **Tip**: If `calicoctl version` returns a `Cluster Type` of `KDD`, you are 
> using the Kubernetes API datastore.
{: .alert .alert-success}

### Prerequisite

You must be on Kubernetes v1.7. If you are not on Kubernetes v1.7,  upgrade to 
Kubernetes v1.7. before continuing.

## Back up your TPR data

We highly recommend backing up your configuration data before proceeding. We only 
need to back up the configuration data stored as TPR resources. In the event the 
migration needs to be halted, the backups will allow you to restore the original data.

> **Note**: Use [`calicoctl` version v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) 
> and [`kubectl` version v1.7.4](https://kubernetes.io/docs/tasks/tools/install-kubectl/) 
> to back up the data. Since we will need [`calicoctl` version v1.4.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.4.1) 
> and [v1.5.0](https://github.com/projectcalico/calicoctl/releases/tag/v1.5.0) 
> for this upgrade, we recommend downloading them both and suffixing the binaries 
> with their respective versions. You can check the version by running 
> `calicoctl version`.
{: .alert .alert-info}
 
Run the following commands in sequence to back up your configuration data:

1. `calicoctl_v1.4 get ippools -o yaml > ippool.yaml`
  
1. `calicoctl_v1.4 get bgppeers -o yaml > bgppeer.yaml`
  
1. `kubectl get globalconfig --all-namespaces -o yaml > tpr-felixconfig.yaml`
  
1. `kubectl get globalbgpconfig --all-namespaces -o yaml > tpr-bgpconfig.yaml`

> **Note**: you may not have some of these resources if you're using {{side.prodname}} in 
> policy-only mode.
{: .alert .alert-info}

## Copy the data from TPR to CRD

1. Create the migration Kubernetes job for your cluster.

   ```
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/master/upgrade/v2.5/manifests/upgrade-job.yaml
   ```

1. Check the job status.

   ```
   kubectl describe job/calico-upgrade-v2.5
   ```

1. Check the upgrade job logs to make sure there aren't any errors. 

   ```
   kubectl logs <upgrade-pod-name>
   ```

> **Tip**: You can get the upgrade job's pod name from the previous command output 
> `Message` field.
{: .alert .alert-success}

## Verify that the data has been copied correctly

Use the following commands to make sure you have all the `IPPools`, `BGPPeers`, 
`GlobalFelixConfig`, and `GlobalBGPConfig` resource configurations you had before 
the migration.

1. `calicoctl_v1.5 get ippools -o wide`
  
1. `calicoctl_v1.5 get bgppeers -o wide` (This is only if you're running {{side.prodname}} BGP networking.)
  
1. `kubectl get globalfelixconfigs.crd.projectcalico.org -o wide`
  
1. `kubectl get globalbgpconfigs.crd.projectcalico.org -o wide`

## Apply updated RBAC manifest

If you have RBAC enabled, apply one of the following RBAC manifests to revoke
access to TPRs from `calico-node`.

**Not using [Canal](https://github.com/projectcalico/canal/tree/master/k8s-install)**

```
kubectl apply -f https://docs.projectcalico.org/v2.5/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml 
```

**Using [Canal](https://github.com/projectcalico/canal/tree/master/k8s-install)**

```
kubectl apply -f https://raw.githubusercontent.com/projectcalico/canal/master/k8s-install/1.7/rbac.yaml 
```
  
## Next steps

Now that you've migrated the data, you can [upgrade the Calico components](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade/).

> **Note**: After upgrading the components, you can delete your TPRs by running the 
> following command: `kubectl delete -f https://raw.githubusercontent.com/projectcalico/calico/master/upgrade/v2.5/manifests/tprs.yaml`
{: .alert .alert-info}

