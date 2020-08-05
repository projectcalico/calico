---
title: Get started with Calico for Windows
description: What you should know about the Calico for Windows at the highest level.
canonical_url: 
---

### Big picture

Understand the {{site.prodNameWindows}} implementation.

### Concepts

#### A hybrid implementation

The {{site.prodNameWindows}} is a hybrid implementation that requires a Linux master node for Calico components, and a Windows cluster for Windows nodes.

### Feature limitations

The following table provides a high-level summary of what is not supported in {{site.prodNameWindows}} at this time. 

| **Main feature** | **Not supported**                                         |
| ---------------- | --------------------------------------------------------- |
| Install          | Installing Windows in privileged container (like docker). |
| Security         | Non-cluster hosts, including automatic host endpoints     |
|                  | Application layer policy (ALP)                            |
| Networking       | Service IP advertisement                                  |
|                  | IPv6 and dual stack                                       |
|                  | VXLAN encapsulation, with cross-subnet                    |
|                  | Setting VXLAN MTU                                         |
|                  | IP-in-IP encapsulation                                    |

More granular restrictions and limitations for Calico networking and network policy are noted in:

- [Known issues and limitations]({{site.baseurl}}/getting-started/windows-calico/known-issues)
- [Determine networking plugin and datastore]({{site.baseurl}}/getting-started/windows-calico/determine-networking)
