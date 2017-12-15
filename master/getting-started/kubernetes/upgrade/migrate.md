---
title: Migrating data from etcdv2 to etcdv3
no_canonical: true
---

> **Important**: Once you begin the migration, stop using `calicoctl` or 
> otherwise modifying the etcdv2 datastore. Such changes are unlikely to 
> be migrated to the new datastore.
{: .alert .alert-danger}

1. Run `calico-upgrade start` to start the v1 to v3 data migration. This begins 
   an interactive session. While existing connectivity will continue as before,
   you cannot add any new endpoints until the migration and upgrade complete.

1. Check the generated reports for details of conversions.

   - If this errors, read logs carefully for any user action.  The script will 
     always try to leave the system in a sensible state (by aborting the upgrade 
     in the event of a failure part way through) - but there may be times where 
     the abort fails (e.g. transient connectivity issue).  The instructions will 
     indicate if the `calico-upgrade abort` script needs to be re-run.

   - If this fails part way through then some v3 data may have been written to 
     etcdv3.  When re-attempting the upgrade, the validation will fail due to v3 
     config being present.  You can either remove all v3 config prior to retrying 
     the upgrade, or use the `--ignore-v3-data` option on the upgrade command to force 
     the upgrade. However, it is possible that the v3 datastore could end up with 
     stray data in this situation.
     
   - After this is started the `calico/node` pods may be restarted by Kubernetes and 
     enter the `CrashLoopBackOff` state. This is expected behavior. They will remain 
     this way until the upgrade is complete.

1. Once you have succeeded in migrating your data from etcdv2 to etcdv3, continue 
   to [Upgrading](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade).