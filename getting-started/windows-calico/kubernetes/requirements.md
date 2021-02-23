---
title: Requirements 
description: Review requirements for the standard install for Calico for Windows.
canonical_url: '/getting-started/windows-calico/kubernetes/requirements'
---

### About {{site.prodnameWindows}}

Because the Kubernetes and {{site.prodname}} control components do not run on Windows yet, a hybrid Linux/Windows cluster is required. {{site.prodnameWindows}} standard installation is distributed as a **.zip archive**. 

### What's supported in this release

✓ Install: Manifest install for Kubernetes clusters

✓ Platforms: Kubernetes, EKS

✓ Networking: 
  - Kubernetes, on-premises: Calico CNI with BGP or VXLAN
  - EKS: VPC CNI, or Calico CNI with BGP or VXLAN

### Requirements

#### CNI and networking options

The following table summarizes the networking options and considerations.

| Networking              | Components                                                   | **Value/Content**                                            |
| ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| {{site.prodname}} BGP   | Windows CNI plugin:<br /><br />calico.exeLinux: {{site.prodname}} for policy and networking | {{site.prodname}}'s native networking approach, supports:<br/>- Auto-configured node-to-node BGP mesh over an L2 fabric<br/>- Peering with external routers for an L3 fabric<br/>- {{site.prodname}} IPAM and IP aggregation (with some limitations)<br/>- Route reflectors (including the new in-cluster route reflector introduced in {{site.prodname}} v3.3). **Note**: Windows node cannot act as route reflectors.<br/>- Kubernetes API datastore driver<br/><br />**AWS users**: If running on AWS, you must disable the source/dest check on your EC2 instances so that hosts can forward traffic on behalf of pods. |
| {{site.prodname}} VXLAN | Windows CNI plugin:<br/>calico.exe<br /><br />Linux: {{site.prodname}} for policy and networking | {{site.prodname}}'s VXLAN overlay, supports:<br/><br />- VXLAN overlay, which can traverse most networks.<br/>- Auto-configured node-to-node routing<br/>- {{site.prodname}} IPAM and IP aggregation (with some limitations)<br/>- Kubernetes API datastore driver<br/>**Note**: VXLAN runs on UDP port 4789 (this is the only port supported by Windows), remember to open that port between your {{site.prodname}} hosts in any firewalls / security groups. |
| Cloud provider          | Windows CNI plugin: win-bridge.exe<br /><br />Linux: {{site.prodname}} policy-only | A useful fallback, particularly if you have a Kubernetes cloud provider that automatically installs inter-host routes. {{site.prodname}} has been tested with the standard **win-bridge.exe** CNI plugin so it should work with any networking provider that ultimately uses win-bridge.exe to network the pod (such as the Azure CNI plugin and cloud provider). |

> **Note**: If Calico CNI with VXLAN is used, BGP must be disabled. See the [installation reference]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.BGPOption).
{: .alert .alert-info}

#### Datastores

Whether you use etcd or Kubernetes datastore (kdd), the datastore for the Windows node/Kubernetes cluster must be the same as the datastore for the Linux control node. (You cannot mix datastores in a {{site.prodnameWindows}} implementation.)

#### Kubernetes version 

- Versions 1.20, 1.19, or 1.18

Earlier versions may work, but we do not actively test {{site.prodnameWindows}} against them, and they may have known issues and incompatibilities.

#### Linux platform 

- At least one Linux Kubernetes worker node to run {{site.prodname}}'s cluster-wide components that meets [Linux system requirements]({{site.baseurl}}/getting-started/kubernetes/requirements), and is installed with {{site.prodname}} v3.12.0+.
- VXLAN or BGP without encapsulation is supported if using Calico CNI. IPIP (default encapsulation mode) is not supported. Use the following command to turn off IPIP.
```bash
calicoctl patch felixconfiguration default -p '{"spec":{"ipipEnabled":false}}'
```
- If using {{site.prodname}} IPAM, strict affinity of IPAM configuration must be set to `true`.
```bash
calicoctl ipam configure --strictaffinity=true
```

>**Note**: {{site.prodnameWindows}} requires four Linux worker nodes in order to meet high-availability requirements for Typha.
{: .alert .alert-info}

#### Windows platform 

- Windows versions:
  - Windows Server 1903 (AKA 19H1) build 18317 or greater
  - Windows Server 2019 / 1809 (RS5) or greater, with [some limitations]({{site.baseurl}}/getting-started/windows-calico/limitations)
  - Windows Server 2019 with DSR support:
    - OS 1809: Build 17763.1432, binary version: 10.0.17763.1432
    - OS 1903: Build 18362.1049, binary version: 10.0.18362.1049
    - OS 1909: Build 18363.1049, binary version: 10.0.18363.1049
- Powershell for the installer
- Make sure the Docker service is installed and running. {% include open-new-window.html text='Install Docker on Windows node' url='https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=Windows-Server' %}.
- If you are using {{site.prodname}} BGP networking, the RemoteAccess service must be installed for the Windows BGP Router.
- Windows nodes support only a single IP pool type (so, if using a VXLAN pool, you should only use VXLAN throughout the cluster).
- TLS v1.2 enabled. For example:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

### Next steps

[Install Calico for Windows]({{site.baseurl}}/getting-started/windows-calico/kubernetes/standard)
