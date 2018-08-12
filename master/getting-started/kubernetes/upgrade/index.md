---
title: Upgrading Calico for Kubernetes
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/upgrade/'
---

## Before you begin

- You must first upgrade to at least {{site.prodname}} [v2.6.5](https://github.com/projectcalico/calico/releases) 
  before you can upgrade to {{site.prodname}} {{site.data.versions[page.version].first.title}}. 
  
  > **Important**: {{site.prodname}} v2.6.5 was a special transitional release that 
  > included changes to enable upgrade to {{site.prodname}} v3.x. Do not skip this step!
  {: .alert .alert-danger}

- If you are using the etcd datastore, upgrade etcd to the latest stable 
  [v3 release](https://coreos.com/etcd/docs/latest/).  

## About upgrading to {{site.prodname}} {{site.data.versions[page.version].first.title}}

The steps to upgrade differ according to your current version and datastore type.

- **Kubernetes API datastore, {{site.prodname}} v2.6.5 or later**: Complete the steps in 
  [Upgrade {{site.prodname}}](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade#upgrading-an-installation-that-uses-the-kubernetes-api-datastore).
  
- **etcd datastore, {{site.prodname}} v3.x**: Complete the steps in 
  [Upgrade {{site.prodname}}](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade#upgrading-an-installation-that-uses-an-etcd-datastore).
  
- **etcd datastore, {{site.prodname}} v2.6.x**: You must migrate your data before
  you can upgrade. Complete the steps in each of the following sections.
  
  1. **[Install and configure calico-upgrade](/{{page.version}}/getting-started/kubernetes/upgrade/setup)** 

  1. **[Test the data migration and check for errors](/{{page.version}}/getting-started/kubernetes/upgrade/test)**

  1. **[Migrate {{site.prodname}} data](/{{page.version}}/getting-started/kubernetes/upgrade/migrate)** 

  1. **[Upgrade {{site.prodname}}](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade#upgrading-an-installation-that-uses-an-etcd-datastore)** 