---
title: Deleting old data
redirect_from: latest/getting-started/openstack/upgrade/delete
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/openstack/upgrade/delete'
---

## About deleting old {{site.prodname}} data

You may need or wish to manually delete {{site.prodname}} data from your etcd datastore under the
following conditions.

- [**etcd**: You succeeded in migrating your data and upgrading to {{site.prodname}} {{site.version}}. After
  running {{site.prodname}} for some time and experiencing no errors, you want to delete
  the old {{site.prodname}} data from the etcdv2 datastore](#deleting-calico-data-from-etcdv2-after-a-successful-migration-and-upgrade).

- [**etcd**: A data migration attempt failed partway through, leaving the etcdv3 datastore
  with some, but not all of your etcvd2 data](#deleting-calico-data-from-etcdv3-after-a-partial-migration).

{% include {{page.version}}/deleting-etcd-v2-v3-data.md %}
