---
title: Get started with Tigera Calico for Windows
description: 
canonical_url: 
---

### Big picture

Understand the basics of a Tigera Calico for Windows implementation.

### Concepts

#### A hybrid implementation

The Tigera Calico for Windows is a hybrid implementation that requires a Linux master node for Calico components, and a Windows cluster for Windows nodes. The implementation is based on the Calico open-source product; you install and upgrade the Linux cluster using the Calico open source product and documentation. However, the product is licensed through Calico Enterprise.

### Before you begin

Tigera Calico for Windows supports all of the following Calico open-source features except:

- Non-cluster hosts 
- Automatic host endpoints
- Service IP advertisement

More granular restrictions and limitations are noted in:

- [Known issues and limitations]({{site.baseurl}}/getting-started/windows-calico/known-issues)
- [Determine networking plugin and datastore]({{site.baseurl}}/getting-started/windows-calico/determine-networking)
