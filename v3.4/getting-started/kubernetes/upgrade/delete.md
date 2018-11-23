---
title: Deleting old data
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/kubernetes/upgrade/delete'
---

## About deleting old Calico data

You may need or wish to manually delete Calico data from your etcd datastore under the
following conditions.
  
- [**etcd**: You succeeded in migrating your data and upgrading to Calico v3.x. After
  running Calico for some time and experiencing no errors, you want to delete
  the old Calico data from the etcdv2 datastore](#deleting-calico-data-from-etcdv2-after-a-successful-migration-and-upgrade).
  
- [**etcd**: A data migration attempt failed partway through, leaving the etcdv3 datastore
  with some, but not all of your etcvd2 data](#deleting-calico-data-from-etcdv3-after-a-partial-migration).

- [**Kubernetes API datastore**: You are using the Kubernetes API datastore and upgraded 
  to Calico v3.x but then downgraded to v2.6.x. You want to clean the Calico v3.x data out of
  the Kubernetes API datastore. If you plan to attempt another upgrade to
  Calico v3.x, this is required.](#deleting-calico-data-from-the-kubernetes-api-datastore-after-a-downgrade).

{% include {{page.version}}/deleting-etcd-v2-v3-data.md %}

## Deleting Calico data from the Kubernetes API datastore after a downgrade

### Prerequisites

- This procedure requires kubectl.
- This procedure should only be done if you have upgraded to v3.x and then
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
datastore](upgrade#upgrading-an-installation-that-uses-the-kubernetes-api-datastore)
to try again.
