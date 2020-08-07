---
title: Requirements 
description: Review requirements for the standard install for Calico for Windows.
canonical_url: '/getting-started/windows-calico/requirements'
---

### About {{site.prodNameWindows}}

Because the Kubernetes and {{site.prodname}} control components do not run on Windows yet, a hybrid Linux/Windows cluster is required. {{site.prodNameWindows}} standard installation is distributed as a **.zip archive**. 

### What's supported in this release

✓ Install: Manifest install for Kubernetes 2 clusters

✓ Platforms: Kubernetes, EKS, and OpenShift

✓ Networking: Calico CNI with VXLAN, or other supported CNI

### Requirements

#### CNI and networking options

The following table summarizes the networking options and considerations.

| Networking              | Components                                                   | **Value/Content**                                            |
| ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| {{site.prodname}} VXLAN | Windows CNI plugin:<br/>calico.exe<br /><br />Linux: {{site.prodname}} for policy and networking | {{site.prodname}}'s VXLAN overlay, supports:<br/><br />- VXLAN overlay, which can traverse most networks.<br/>- Auto-configured node-to-node routing<br/>- {{site.prodname}} IPAM and IP aggregation (with some limitations)<br/>- Both etcd and Kubernetes API datastore drivers<br/><br />**Requires**:<br/>- Windows 1903 insider preview 18317 or greater<br/>- Windows Server 2019 / 1809 (RS5), with network policy limitations.<br /><br />**Note**: VXLAN runs on UDP port 4789 (this is the only port supported by Windows), remember to open that port between your {{site.prodname}} hosts in any firewalls / security groups. |
| Cloud provider          | Windows CNI plugin: win-bridge.exe<br /><br />Linux: {{site.prodname}} policy-only | A useful fallback, particularly if you have a Kubernetes cloud provider that automatically installs inter-host routes. {{site.prodname}} has been tested with the standard **win-bridge.exe** CNI plugin so it should work with any networking provider that ultimately uses win-bridge.exe to network the pod (such as the Azure CNI plugin and cloud provider). |

#### Datastores

Whether you use etcd or Kubernetes datastore (kdd), the datastore for the Windows node/Kubernetes cluster must be the same as the datastore for the Linux control node. (You cannot mix datastores in a {{site.prodNameWindows}} implementation.)

#### Kubernetes version 

- Versions 1.17, 1.16, or 1.15

Earlier versions may work, but we do not actively test {{site.prodNameWindows}} against them, and they may have known issues and incompatibilities.

#### Linux platform 

- At least one Linux Kubernetes worker node to run {{site.prodname}}'s cluster-wide components that meets [Linux system requirements]({{site.baseurl}}/getting-started/kubernetes/requirements), and is installed with {{site.prodname}} v3.12.0+

#### Windows platform 

- Windows versions:
  - Windows Server 1903 (AKA 19H1) build 18317 or greater
  - Windows Server 2019 / 1809 (RS5) or greater, with [some limitations]({{site.baseurl}}/getting-started/windows-calico/limitations)
- Powershell for the installer
- Windows nodes support only a single IP pool type (so, if using a VXLAN pool, you should only use VXLAN throughout the cluster).
- TLS v1.2 enabled. For example:

```
PS C:\> [Net.ServicePointManager]::SecurityProtocol = `
                               [Net.SecurityProtocolType]::Tls12
```
### Next steps

[Install {{site.prodNameWindows}}]({{site.baseurl}}/getting-started/windows-calico/standard)
