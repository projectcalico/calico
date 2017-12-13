---
title: Upgrading Calico for Kubernetes
redirect_from: latest/getting-started/kubernetes/upgrade
---

You should be able to upgrade to {{side.prodname}} {{site.data.versions[page.version].first.title}} 
from {{side.prodname}} v2.0 or later following the instructions in this section.

While an upgrade from any version 2.0 or later might work, we have tested and 
verified only the following versions. We strongly discourage attempting to upgrade 
a production cluster that does not conform to the below. Should you require this, 
contact Tigera for assistance. 

| {{side.prodname}} version | Datastore type           | Kubernetes version  |
| ------------------------- | ------------------------ | ------------------- |
| v2.5.x                    | Kubernetes API datastore | v1.8                |
| v2.5.x                    | etcd                     | v1.8                |
| v2.5.x                    | etcd                     | v1.7                |
| v2.4.x                    | etcd                     | v1.8                |
| v2.4.x                    | etcd                     | v1.7                |

Upgrades from versions not shown above may require a policy conversion, a data migration, 
or both.

1. **[Convert policies](/{{page.version}}/getting-started/kubernetes/upgrade/convert)** 

   If you are using the Kubernetes `NetworkPolicy` API and you meet the following criteria, 
   you must convert your policies before you can upgrade. If you are not using the 
   Kubernetes `NetworkPolicy` API, you don't need to perform this task.

   | Current version     | Datastore type           | Conversion required? |
   | ------------------- | ------------------------ | -------------------- |
   | earlier than v2.3.0 | Kubernetes API datastore | Yes                  |
   | earlier than v2.4.0 | etcd                     | Yes                  |

1. **[Migrate data](/{{page.version}}/getting-started/kubernetes/upgrade/migrate)** 

   If you are using the Kubernetes API datastore and upgrading from a version of
   {{side.prodname}} earlier than v2.5, you must complete a data migration before you can upgrade.

1. **[Upgrade components](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade)** 

   Once you have completed any necessary prerequisite steps, you can go ahead and 
   upgrade the {{side.prodname}} components.
