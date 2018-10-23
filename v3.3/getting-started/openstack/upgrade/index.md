---
title: Upgrading Calico
redirect_from: latest/getting-started/openstack/upgrade/index
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/openstack/upgrade/'
---
## Upgrade procedure
These documents detail the procedure for upgrading {{site.prodname}} in an OpenStack system. 
If a release does not upgrade a particular component, you should skip the steps for that component.

> **Important**: You will
> be unable to issue API requests to your OpenStack system during the
> procedure. Please plan your upgrade window accordingly, and see the
> [Service Impact](#service-impact) section for more details.
{: .alert .alert-danger}

## Service impact

During the upgrade, **all VMs will continue to function normally**:
there should be no impact on the data plane. However, control plane
traffic may fail at different points throughout the upgrade.

Generally, users should be prevented from creating or updating virtual
machines during this procedure, as these actions will fail. VM deletion
*may* succeed, but will likely be delayed until the end of the upgrade.

For this reason, we highly recommend planning a maintenance window for
the upgrade. During this window, you should disable all user API access
to your OpenStack deployment.


## Before you begin

- You must first [upgrade](/v2.6/getting-started/openstack/upgrade) 
  to {{site.prodname}} [v2.6.x](https://github.com/projectcalico/calico/releases) 
  before you can upgrade to {{site.prodname}} 
  {{site.data.versions[page.version].first.title}}. 
- If you have {{site.prodname}} data which was not generated from OpenStack networks/security groups (e.g. Host Endpoints, Host Protection policies, etc), you will need to have `etcdctl` installed.

## Upgrade steps

1. Set up an etcdv3 cluster, if you don't already have etcdv3 capability, either by [upgrading the etcd software of your existing etcdv2 cluster](https://coreos.com/etcd/docs/latest/upgrades/upgrade_3_0.html), or by [installing an etcdv3 cluster on new servers](https://coreos.com/etcd/docs/latest/op-guide/clustering.html).
  
   > **Tip**: etcd v3.x still supports the etcdv2 API, as used by {{site.prodname}} v2.6.x.
   > However, {{site.prodname}} v3.0.0+ does not support the etcdv2 API.  The upgrade steps below
   > move the data from the etcdv2 API to the etcdv3 API.  This requires an etcd v3.x server.
   {: .alert .alert-success}

1. If you have added {{site.prodname}} objects in addition to those that are derived automatically (by our Neutron driver) from OpenStack networks/security groups (e.g. Host Endpoints, Host Protection policies, etc) you will need to follow these additional steps to migrate that data:
       
    1. **[Install and configure calico-upgrade](/{{page.version}}/getting-started/openstack/upgrade/setup)** 
    
    1. **[Test the data migration and check for errors](/{{page.version}}/getting-started/openstack/upgrade/test)**
    
    1. **[Migrate {{site.prodname}} data](/{{page.version}}/getting-started/openstack/upgrade/migrate)** 

1. **[Upgrade {{site.prodname}} packages](/{{page.version}}/getting-started/openstack/upgrade/upgrade)**, first on each compute node, then on the controllers. 

1. **[Delete old data](/{{page.version}}/getting-started/openstack/upgrade/delete#deleting-calico-data-from-etcdv2-after-a-successful-migration-and-upgrade)** from etcd.

1. Finally, if you have any calico resource manifests stored offline (e.g. files checked into code management systems), you should update them to the new API using the conversion tool:
  **[Convert any offline {{site.prodname}} data from V1 to V3](/{{page.version}}/getting-started/openstack/upgrade/convert)** 
