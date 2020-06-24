---
title: Requirements
description: Review requirements for installing Calico for Windows.
canonical_url: '/getting-started/kubernetes/windows-calico/requirements'
---

### Distribution 

{{site.prodNameWindows}} is distributed as a **.zip archive**.  

### Node requirements 

Because the Kubernetes and {{site.prodname}} control components do not run on Windows yet, a hybrid Linux/Windows cluster is required. 

### Linux platform requirements

- At least one Linux Kubernetes worker node to run {{site.prodname}}'s cluster-wide components that meets [Linux system requirements]({{site.baseurl}}/getting-started/kubernetes/requirements). 
- {{site.prodname}} for Linux v3.12.0+

### Kubernetes version requirements 

- 1.15
- 1.17

Earlier versions may have known issues and incompatibilities and may work, but we do not actively test {{site.prodNameWindows}} against them.

### Windows platform requirements

- Windows version:
  - Windows Server 2019 / 1809 (RS5) or greater, with [some limitations]({site.baseurl}}/getting-started/windows-calico/determine-networking)
  - Windows Server 1903 (AKA 19H1) build 18317 or greater
- Powershell for the installer
- {{site.prodname}}'s BGP networking mode requires the **RemoteAccess service** to be installed to provide the Windows BGP Router
- Windows nodes support only a single IP pool type (so, if using a VXLAN pool, you should only use VXLAN throughout the cluster).
- TLS v1.2 enabled. For example:

  ```
  PS C:\> [Net.ServicePointManager]::SecurityProtocol = `
                               [Net.SecurityProtocolType]::Tls12
  ```
### Next steps

[Install {{site.prodNameWindows}}]({site.baseurl}}/getting-started/windows-calico/install)
