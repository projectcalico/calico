---
title: Upgrading Calico for Kubernetes
no_canonical: true
---


## Prerequisites

- You must [upgrade](/v2.6/getting-started/kubernetes/upgrade) 
  to a tagged release of {{site.prodname}} [v2.6.5](https://github.com/projectcalico/calico/releases) before you can upgrade to {{site.prodname}} {{site.data.versions[page.version].first.title}}. 

- An [etcdv3 cluster](https://coreos.com/etcd/docs/latest/). 


## Kubernetes API datastore upgrade steps

If you are using the Kubernetes API datastore, complete the steps in [Upgrade Calico](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade).

## etcd datastore upgrade steps

If you are connecting directly to an etcd datastore, complete each 
of the following in sequence.

1. **[Install and configure calico-upgrade](/{{page.version}}/getting-started/kubernetes/upgrade/setup)** 

1. **[Test the data migration and check for errors](/{{page.version}}/getting-started/kubernetes/upgrade/test)**

1. **[Migrate Calico data](/{{page.version}}/getting-started/kubernetes/upgrade/migrate)** 

1. **[Upgrade Calico](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade)** 