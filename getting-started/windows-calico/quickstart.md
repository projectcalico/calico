---
title: Quickstart
description: Install Calico for Windows on a Kubernetes cluster for testing or development.
canonical_url: '/getting-started/windows-calico/quickstart'
---

### Big picture

Install {{site.prodnameWindows}} on your Kubernetes cluster in approximately 5 minutes.

### Concepts

{{site.prodnameWindows}} is a hybrid implementation that requires a Linux control node for {{site.prodname}} components, and a Windows cluster for Windows nodes.

### Before you begin

**Datastore requirements**

Whether you use etcd or Kubernetes datastore (kdd), the datastore for the Windows node/Kubernetes cluster must be the same as the datastore for the Linux control node. (You cannot mix datastores in a {{site.prodnameWindows}} implementation.)

**Kubernetes cluster requirements**
- Kubernetes clusters with versions 1.18, 1.17, or 1.16

**Windows node requirements**
- Versions:  
  - Windows Server 1809 (build Build 17763.1432 or greater)
  - Windows Server 1903 (AKA 19H1 build 18362.1049 or greater)
  - Windows Server 1909 (AKA 19H2 build 18362.1049 or greater), with Docker service enabled
- Remote access to the Windows node via Remote Desktop Protocol (RDP) or Windows Remote Management (WinRM)
- Additionally, for EKS:
    - The VPC controllers must be installed be installed to run Windows pods.
    - The Windows instance role must have access to `secrets` in the kube-system namespace.

**Linux control node requirements**
- Installed with {{site.prodname}} v3.12+
- If {{site.prodname}} networking is being used:
    - Networking must be VXLAN. (Note: for EKS, networking is set to none since AWS VPC networking is used.)
    - Strict affinity must be set to `true`

### How to

- [Configure strict affinity for clusters using {{site.prodname}} networking](#configure-strict-affinity-for-clusters-using-calico-networking)
- [Install {{site.prodnameWindows}}](#install-calico-for-windows)
- [Configure installation parameters](#configure-installation-parameters)

#### Configure strict affinity for clusters using {{site.prodname}} networking

For Linux control nodes using {{site.prodname}} networking, strict affinity must be set to `true`.
This is required to prevent Linux nodes from borrowing IP addresses from Windows nodes:

```bash
calicoctl ipam configure --strictaffinity=true
```

#### Install {{site.prodnameWindows}}

The following steps install a Kubernetes cluster on a single Windows node, with a Linux control node.

- **Kubernetes**
  
  The geeky details of what you get by default:
  {% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:BGP,Datastore:Kubernetes' %}

- **EKS**

  The geeky details of what you get by default:
  {% include geek-details.html details='Policy:Calico,IPAM:AWS,CNI:AWS,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

{% tabs %}
  <label:Kubernetes,active:true>
  <%
  
1. Disable BGP since we are using VXLAN:
   ```bash
   kubectl patch installation default --type=merge -p '{"spec": {"calicoNetwork": {"bgp": "Disabled"}}}'
   ```

1. Prepare directory for Kubernetes files on Windows node.

   ```powershell
   mkdir c:\k
   ```

1. Copy the Kubernetes kubeconfig file from the master node (default, Location $HOME/.kube/config), to **c:\k\config**.

1. Download the powershell script, **install-calico-windows.ps1**.

   ```powershell
   Invoke-WebRequest {{ "/scripts/install-calico-windows.ps1" | absolute_url }} -OutFile c:\install-calico-windows.ps1
   ```

1. Run install-calico-windows.ps1 with correct parameters. The powershell script will perform following tasks.

   - Downloads {{site.prodnameWindows}} release binary and other Windows utilities files.
   - Downloads Kubernetes binaries.
   - Configures {{site.prodnameWindows}} and starts the Calico service.

1. To skip any of the above tasks, see [Configure installation parameters](#configure-installation-parameters).

1. Run install-calico-windows.ps1 for your datastore with parameters for your implementation.
   You do not need to pass a parameter if the default value of the parameter is correct for you cluster.

   **Kubernetes datastore (default)**

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <your Kubernetes version (e.g. 1.18.6)> \
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> \
                                 -DNSServerIPs <your DNS service IP (default 10.96.0.10)>
   ```

   **etcd datastore**

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <your Kubernetes version (e.g. 1.18.6)> \
                                 -Datastore etcdv3
                                 -EtcdEndpoints <your etcd endpoint ip>
                                 -EtcdTlsSecretName <your etcd TLS secret name in kube-system namespace> (default no etcd TLS secret is used)
                                 -EtcdKey <path to key file> (default not using TLS)
                                 -EtcdCert <path to cert file> (default not using TLS)
                                 -EtcdCaCert <path to ca cert file> (default not using TLS)
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> \
                                 -DNSServerIPs <your DNS server IPs (default 10.96.0.10)>
   ```

   > **Note**: You do not need to pass a parameter if the default value of the parameter is correct for you cluster.
   {: .alert .alert-info}


1. Verify that the {{site.prodname}} services are running.

   ```powershell
   PS C:\> Get-Service -Name CalicoNode

   Status   Name               DisplayName
   ------   ----               -----------
   Running  CalicoNode         Calico Windows Startup


   PS C:\> Get-Service -Name CalicoFelix

   Status   Name               DisplayName
   ------   ----               -----------
   Running  CalicoFelix        Calico Windows Agent
   ```
1. Install and start kubelet/kube-proxy service. Execute following powershell script/commands.

   ```powershell
   C:\CalicoWindows\kubernetes\install-kube-services.ps1
   Start-Service -Name kubelet
   Start-Service -Name kube-proxy
   ```
1. Verify kubelet/kube-proxy services are running.

   ```powershell
   PS C:\> Get-Service -Name kubelet

   Status   Name               DisplayName
   ------   ----               -----------
   Running  kubelet            kubelet service


   PS C:\> Get-Service -Name kube-proxy

   Status   Name               DisplayName
   ------   ----               -----------
   Running  kube-proxy         kube-proxy service
   ```

%>

  <label:EKS>
  <%

1. Prepare directory for Kubernetes files on Windows node.

   ```powershell
   mkdir c:\k
   ```

1. [Install kubectl](https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html#windows){:target="_blank"} and move the kubectl binary to **c:\k**.

1. Download the powershell script, **install-calico-windows.ps1**.

   ```powershell
   Invoke-WebRequest {{site.url}}/scripts/install-calico-windows.ps1 -OutFile c:\install-calico-windows.ps1
   ```

1. Run install-calico-windows.ps1 with correct parameters. The powershell script will perform following tasks.

   - Downloads {{site.prodnameWindows}} release binary and other Windows utilities files.
   - Downloads Kubernetes binaries.
   - Configures {{site.prodnameWindows}} and starts the Calico service.

1. To skip any of the above tasks, see [Configure installation parameters](#configure-installation-parameters).

1. Run install-calico-windows.ps1 for your datastore with parameters for your implementation.
   You do not need to pass a parameter if the default value of the parameter is correct for you cluster.

   **Kubernetes datastore (default)**

   ```powershell
   c:\install-calico-windows.ps1 -ServiceCidr <your service cidr (default 10.96.0.0/12)> \
                                 -DNSServerIPs <your DNS service IP (default 10.96.0.10)>
   ```

   **etcd datastore**

   ```powershell
   c:\install-calico-windows.ps1 -Datastore etcdv3
                                 -EtcdEndpoints <your etcd endpoint ip>
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> \
                                 -DNSServerIPs <your DNS server IPs (default 10.96.0.10)>
   ```

   > **Note**: You do not need to pass a parameter if the default value of the parameter is correct for you cluster.
   {: .alert .alert-info}


1. Verify that the {{site.prodname}} services are running.

   ```powershell
   PS C:\> Get-Service -Name CalicoNode

   Status   Name               DisplayName
   ------   ----               -----------
   Running  CalicoNode         Calico Windows Startup


   PS C:\> Get-Service -Name CalicoFelix

   Status   Name               DisplayName
   ------   ----               -----------
   Running  CalicoFelix        Calico Windows Agent
   ```

1. Verify kubelet and kube-proxy services are running.

   ```powershell
   PS C:\> Get-Service -Name kubelet

   Status   Name               DisplayName
   ------   ----               -----------
   Running  kubelet            kubelet service


   PS C:\> Get-Service -Name kube-proxy

   Status   Name               DisplayName
   ------   ----               -----------
   Running  kube-proxy         kube-proxy service
   ```

%>

  {% endtabs %}

#### Configure installation parameters

| **Parameter Name** | **Description**                                           | **Default** |
| ------------------ | --------------------------------------------------------- |-------------|
| KubeVersion        | Version of Kubernetes binaries to use. If value is empty string (default), the {{site.prodnameWindows}} installation script does not download Kubernetes binaries and run Kubernetes service. Use the default for managed public cloud. | "" |
| DownloadOnly       | Download without installing {{site.prodnameWindows}}. Set to `yes` to manually install and configure {{site.prodnameWindows}}. For example, {{site.prodnameWindows}} the hard way. | no |
| Datastore          | {{site.prodnameWindows}} datastore type [`kubernetes` or `etcdv3`] for reading endpoints and policy information. | kubernetes |
| EtcdEndpoints      | Comma-delimited list of etcd connection endpoints. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379`. Valid only if `Datastore` is set to `etcdv3`. | "" |
| EtcdTlsSecretName  | Name of a secret in `kube-system` namespace which contains `etcd-key`, `etcd-cert`, `etcd-ca` for automatically configuring TLS. Either use this or parameters `EtcdKey`, `EtcdCert`, `EtcdCaCert` below. | "" |
| EtcdKey            | Path to key file for etcd TLS connection. | "" |
| EtcdCert           | Path to certificate file for etcd TLS connection. | "" |
| EtcdCaCert         | Path to CA certificate file for etcd TLS connection. | "" |
| ServiceCidr        | Service IP range of the Kubernetes cluster. Not required for most managed Kubernetes clusters. Note: EKS has non-default value. | 10.96.0.0/12 |
| DNSServerIPs       | Comma-delimited list of DNS service IPs used by Windows pod. Not required for most managed Kubernetes clusters. Note: EKS has a non-default value. | 10.96.0.10 |

Congratulations! You now have a Kubernetes cluster with {{site.prodnameWindows}} and a Linux control node.

### Next steps

You can now use the {{site.prodname}} Linux-based docs site for your documentation. Before you continue, review the [Limitations and known issues]({{site.baseurl}}/getting-started/windows-calico/limitations) to understand the features (and sections of documentation) that do not apply to Windows.
