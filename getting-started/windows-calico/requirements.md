---
title: Requirements
description: Review requirements for installing Calico for Windows.
canonical_url: '/getting-started/kubernetes/requirements'
---

### License and distribution 

Calico for Windows is [licensed]({{site.baseurl}}/getting-started/calico-enterprise) and distributed as a **.zip archive**.  

### Node requirements 

Because the Kubernetes and Calico "control" components do not run on Windows yet, a hybrid Linux/Windows cluster is required. 

### Linux platform requirements

- At least one Linux Kubernetes worker node to run Calico's cluster-wide components that meets [Linux system requirements]({{site.baseurl}}/getting-started/kubernetes/requirements). 
- Calico for Linux v3.12.0+

### Kubernetes version requirements 

- 1.15
- 1.17

Earlier versions may have known issues and incompatibilities and may work, but we do not actively test Calico for Windows against them.

### Windows platform requirements

- Windows version:
  - Windows Server 2019 / 1809 (RS5) or greater, with [some limitations](#determine-your-network-plugin)
  - Windows Server 1903 (AKA 19H1) build 18317 or greater
- Powershell for the installer
- Calico's BGP networking mode requires the **RemoteAccess service** to be installed to provide the Windows BGP Router
- Windows nodes support only a single IP pool type (so, if using a VXLAN pool, you should only use VXLAN throughout the cluster).
- TLS v1.2 enabled. For example:
  ```
  PS C:\> [Net.ServicePointManager]::SecurityProtocol = `
                               [Net.SecurityProtocolType]::Tls12
  ```

### Next steps

[Install Tigera Calico for Windows]()