---
title: Installing and configuring calico-upgrade
redirect_from: latest/getting-started/openstack/upgrade/setup
canonical_url: 'https://docs.projectcalico.org/v3.4/getting-started/openstack/upgrade/setup'
---

## Requirements

A host with connectivity to the existing etcdv2 datastore as well as the
target etcdv3 cluster. The host must be AMD64 and running one of the following:

- OS X or macOS
- Linux
- Windows

## Before you begin

Set the version flag.  On the control node:
```
etcdctl set /calico/v1/config/CalicoVersion v2.6.5-7
```

> calico-upgrade will not operate on a etcdv2 datastore that does not have this key set.
{: .alert .alert-danger}

{% include {{page.version}}/install-calico-upgrade.md %}

## Configuring calico-upgrade

### About configuring calico-upgrade

You must configure `calico-upgrade` so that it can connect to both of the
following:

- [The existing etcdv2 datastore used by {{site.prodname}} v2.6.x](#configuring-calico-upgrade-to-connect-to-the-etcdv2-datastore)

- [The etcdv3 cluster you plan to use for {{site.prodname}} v3.1](#configuring-calico-upgrade-to-connect-to-the-etcdv3-cluster)

{% include {{page.version}}/config-calico-upgrade-etcd.md %}


  
## Next steps

After configuring `calico-upgrade` to communicate with the existing etcdv2 instance
and the target etcdv3 cluster, continue to [Testing the data migration](/{{page.version}}/getting-started/openstack/upgrade/test).
