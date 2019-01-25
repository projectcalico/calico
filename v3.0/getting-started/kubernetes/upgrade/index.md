---
title: Upgrading Calico for Kubernetes
canonical_url: https://docs.projectcalico.org/v3.5/getting-started/kubernetes/upgrade/
---

Upgrading to this release of {{site.prodname}} from a pre-v3.0 release may require some manual steps, depending on
your choice of datastore.

## Before you begin

- You must first [upgrade](/v2.6/getting-started/kubernetes/upgrade) 
  to {{site.prodname}} [v2.6.5](https://github.com/projectcalico/calico/releases) 
  (or a later v2.6.x release) before you can upgrade to {{site.prodname}} 
  {{site.data.versions[page.version].first.title}}. 
  
  > **Important**: {{site.prodname}} v2.6.5 was a special transitional release that included changes to enable 
  > upgrade to v3.0.1+; do not skip this step!
  {: .alert .alert-danger}

- If you are using the etcd datastore, you should upgrade etcd to the latest stable 
  [v3 release](https://coreos.com/etcd/docs/latest/).  
  
  > **Tip**: etcd v3.x still supports the etcd v2 API, as used by {{site.prodname}} v2.6.x.
  > However, {{site.prodname}} v3.0.0+ does not support the etcd v2 API.  The upgrade steps below
  > move the data from the etcd v2 API to the etcd v3 API.  This requires an etcd v3.x server.
  {: .alert .alert-success}

## Kubernetes API datastore upgrade steps

If you are using the Kubernetes API datastore, complete the steps in 
[Upgrade {{site.prodname}}](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade).

## etcd datastore upgrade steps

If you are using the etcd datastore then a manual migration step is required, using the 
`calico-upgrade` tool.  To complete the upgrade follow these steps in sequence:

1. **[Install and configure calico-upgrade](/{{page.version}}/getting-started/kubernetes/upgrade/setup)** 

1. **[Test the data migration and check for errors](/{{page.version}}/getting-started/kubernetes/upgrade/test)**

1. **[Migrate {{site.prodname}} data](/{{page.version}}/getting-started/kubernetes/upgrade/migrate)** 

1. **[Upgrade {{site.prodname}}](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade)** 