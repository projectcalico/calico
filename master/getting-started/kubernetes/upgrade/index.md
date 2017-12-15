---
title: Upgrading Calico for Kubernetes
redirect_from: latest/getting-started/kubernetes/upgrade
no_canonical: true
---


## Prerequisites

- {{site.prodname}} {{site.data.versions[page.version].first.title}} 
supports upgrades from {{site.prodname}} v2.6.4 or later. You must [upgrade](/v2.6/getting-started/kubernetes/upgrade) 
to {{site.prodname}} v2.6.4 before you can upgrade to {{side.prodname}} 
{{site.data.versions[page.version].first.title}}. 

- An [etcdv3 server](https://coreos.com/etcd/docs/latest/). 

## Upgrade steps

To upgrade {{site.prodname}} v2.6.4 or later to {{site.prodname}} {{site.data.versions[page.version].first.title}}, complete each of the following in sequence.

1. **[Install and configure calico-upgrade](/{{page.version}}/getting-started/kubernetes/upgrade/setup)** 

1. **[Test the data migration and check for errors](/{{page.version}}/getting-started/kubernetes/upgrade/test)**

1. **[Migrate data from your etcdv2 datastore to your etcdv3 datastore](/{{page.version}}/getting-started/kubernetes/upgrade/migrate)** 

1. **[Upgrade components](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade)** 

1. **[Convert your calicoctl manifests (optional)](/{{page.version}}/getting-started/kubernetes/upgrade/convert)** 
