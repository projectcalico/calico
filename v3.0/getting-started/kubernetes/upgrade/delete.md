---
title: Deleting old data
sitemap: false 
canonical_url: https://docs.projectcalico.org/v3.1/getting-started/kubernetes/upgrade/delete
---

## About deleting old Calico data

You may need or wish to manually delete Calico data from your etcd datastore under the
following conditions.
  
- [**etcd**: You succeeded in migrating your data and upgrading to Calico v3.0. After
  running Calico for some time and experiencing no errors, you want to delete
  the old Calico data from the etcdv2 datastore.](#deleting-calico-data-from-etcdv2-after-a-successful-migration-and-upgrade)
  
- [**etcd**: A data migration attempt failed partway through, leaving the etcdv3 datastore
  with some, but not all of your etcvd2 data.](#deleting-calico-data-from-etcdv3-after-a-partial-migration)

- [**Kubernetes API datastore**: You are using the Kubernetes API datastore and upgraded 
  to Calico v3.0 but then downgraded to v2.6.5. You want to clean the Calico v3.0 data out of
  the Kubernetes API datastore. If you plan to attempt another upgrade to
  Calico v3.0, this is required](#deleting-calico-data-from-the-kubernetes-api-datastore-after-a-downgrade)

## Deleting Calico data from etcdv2 after a successful migration and upgrade

### Prerequisite

This procedure requires etcdctl v3. The etcdctl tool is installed along with etcd. To install just etcdctl, [download the etcd release binary](https://github.com/coreos/etcd/releases), untar it, and extract the etcdctl binary.
  
### Deleting Calico data from etcdv2

> **Note**: You must pass the same options you 
> [configured `calico-upgrade` with](/{{page.version}}/getting-started/kubernetes/upgrade/setup#configuring-calico-upgrade-to-connect-to-the-etcdv2-datastore) 
> to etcdctl to achieve a connection. We include just the `--endpoint` flag in the
> following commands. Depending on your etcd configuration, you may need to include
> additional parameters in these commands. Refer to the 
> [etcdctl documentation for etcdv2 datastores](https://github.com/coreos/etcd/blob/master/etcdctl/READMEv2.md) 
> for more information about the flags and environment variables.
{: .alert .alert-info}

1. Issue the following command to retrieve a list of all of the Calico keys.
   
   ```
   etcdctl --endpoint=<etcdv2-hostname:port> ls /calico --recursive
   ```
   
1. Issue the following command to delete the {{site.prodname}} keys.
   
   ```
   etcdctl --endpoint=<etcdv2-hostname:port> rm /calico/ --recursive 
   ```
   
1. Issue the following command to confirm that the {{site.prodname}} keys were deleted.
   
   ```
   etcdctl --endpoint=<etcdv2-hostname:port> ls /calico --recursive
   ```
   
   It should return `Error: 100: Key not found (/calico) [1186]`.
   
1. Congratulations! You've cleaned {{site.prodname}}'s etcdv2 datastore of {{site.prodname}}
   data. 


## Deleting Calico data from etcdv3 after a partial migration

### Prerequisites

This procedure requires etcdctl v3. The etcdctl tool is installed along with etcd. To install just etcdctl, [download the etcd release binary](https://github.com/coreos/etcd/releases), untar it, and extract the etcdctl binary.
  

### Deleting Calico data from etcdv3

> **Note**: You must pass the same options you 
> [configured `calico-upgrade` with](/{{page.version}}/getting-started/kubernetes/upgrade/setup#configuring-calico-upgrade-to-connect-to-the-etcdv3-cluster) 
> to etcdctl to achieve a connection. We include just the `--endpoints` flag in the
> following commands. Depending on your etcd configuration, you may need to include
> additional parameters in these commands or set environment variables. Refer to the 
> [etcdctl documentation for etcdv3 datastores](https://github.com/coreos/etcd/blob/master/etcdctl/README.md) 
> for more information about the flags and environment variables.
{: .alert .alert-info}

   
1. Issue the following command to retrieve a list of all of the Calico keys.
   
   ```
   ETCDCTL_API=3 etcdctl --endpoints=<etcdv3-hostname:port> get /calico/ --prefix --keys-only
   ```
   
1. Issue the following command to delete the {{site.prodname}} keys.
   
   ```
   ETCDCTL_API=3 etcdctl --endpoints=<etcdv3-hostname:port> del /calico/ --prefix 
   ```
   
   It returns the number of keys it deleted.
   
1. Issue the following command to confirm that the {{site.prodname}} keys were deleted.
   
   ```
   ETCDCTL_API=3 etcdctl --endpoints=<etcdv3-hostname:port> get /calico/ --prefix --keys-only
   ```
   
   It should return nothing.
   
1. Congratulations! You've cleaned {{site.prodname}}'s etcdv3 datastore of {{site.prodname}}
   data. 
   
### Next steps

Return to [Migrate your data](/{{page.version}}/getting-started/kubernetes/upgrade/migrate)
to try again.

## Deleting Calico data from the Kubernetes API datastore after a downgrade

### Prerequisites

- This procedure requires kubectl.
- This procedure should only be done if you have upgraded to v3.0+ and then
  downgraded to your previous version.

### Deleting Calico data from the Kubernetes API datastore

1. Check that the data exists in the Kubernetes API datastore. Issue the
   following.

   ```
   kubectl get crd
   ```

1. Verify the output contains lines with the following:
   - `bgpconfigurations.crd.projectcalico.org`
   - `felixconfigurations.crd.projectcalico.org`
   - `clusterinformations.crd.projectcalico.org`
   - `networkpolicies.crd.projectcalico.org`


1. Issue the following commands to delete the {{site.prodname}} data.

   ```
   kubectl delete crd bgpconfigurations.crd.projectcalico.org
   kubectl delete crd felixconfigurations.crd.projectcalico.org
   kubectl delete crd clusterinformations.crd.projectcalico.org
   kubectl delete crd networkpolicies.crd.projectcalico.org
   ```

   It returns the number of keys it deleted.

1. Issue the following command to confirm that the {{site.prodname}} data was deleted.
   Verify the output does not contain the `crd`s deleted above.

   ```
   kubectl get crd
   ```

1. Congratulations! You've cleaned {{site.prodname}}'s Kubernetes API
   datastore.

### Next steps

Return to [Upgrading a self-hosted installation that uses the Kubernetes API
datastore](upgrade#upgrading-a-self-hosted-installation-that-uses-the-kubernetes-api-datastore)
to try again.
