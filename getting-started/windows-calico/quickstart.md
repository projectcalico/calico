---
title: Quickstart
description: Install Calico for Windows on a Kubernetes cluster for testing or development.
canonical_url: '/getting-started/windows-calico/quickstart'
---

### Big picture

Install {{site.prodNameWindows}} on your Kubernetes cluster in approximately 5 minutes.

### Concepts

{{site.prodNameWindows}} is a hybrid implementation that requires a Linux control node for {{site.prodname}} components, and a Windows cluster for Windows nodes.

### Before you begin

**Datastore requirements**

Whether you use etcd or Kubernetes datastore (kdd), the datastore for the Windows node/Kubernetes cluster must be the same as the datastore for the Linux control node. (You cannot mix datastores in a {{site.prodNameWindows}} implementation.)

**Kubernetes cluster requirements**
- Versions 1.17, 1.16, or 1.15

**Windows node requirements**
- Windows Server 1903 (AKA 19H1) build 18317 or greater, with Docker service enabled

**Linux control node requirements**
- Installed with {{site.prodname}} v3.12+ 
- {{site.prodname}} networking is VXLAN

### How to

- [Install Calico for Windows](#install-calico-for-windows)
- [Configure installation parameters](#configure-installation-parameters)

#### Install Calico for Windows

The following steps install a Kubernetes cluster on a single Windows node, with a Linux control node. 

{% tabs %}
  <label:Kubernetes,active:true>
  <%
#### Install {{site.prodNameWindows}}

1. Prepare directory for Kubernetes files on Windows node.
   ```powershell
   mkdir c:\k
   ```

1. Copy the Kubernetes certificate file from the master node (default, Location $HOME/.kube/config), to **c:\k**.

1. Download the powershell script, **install-calico-windows.ps1**.

   ```powershell
      Invoke-WebRequest https://github.com/projectcalico/calico/releases/download/v3.16.0/install-calico-windows.ps1 -OutFile c:\install-calico-windows.ps1
      ```

1. Run install-calico-windows.ps1 with correct parameters. The powershell script will perform following tasks.
   
   - Downloads {{site.prodNameWindows}} release binary and other Windows utilities files.
   - Downloads Kubernetes binaries. 
   - Configures {{site.prodNameWindows}} and starts the Calico service.  

1. To skip any of the above tasks, see [Installation script parameters](#installation-script-parameters).  

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
 
 The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:BGP,Datastore:kdd' %}     
%>

  <label:EKS>
  <%
steps…

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:BGP,Datastore:kdd' %}   
%>

<label:OpenShift>
  <%
steps…

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:BGP,Datastore:kdd' %}   
%>

  {% endtabs %}


#### Installation script parameters

| **Parameter Name** | **Description**                                         | **Default** |
| ------------------ | --------------------------------------------------------- |-------------|
| KubeVersion        | Version of Kubernetes binaries to use. If value is empty string (default), the {{site.prodNameWindows}} installation script does not download Kubernetes binaries and run Kubernetes service. Use default for managed public cloud (for example, EKS). | "" |
| DownloadOnly       | Download without installing {{site.prodNameWindows}}. Set to `yes` to manually install and configure {{site.prodNameWindows}}. For example, {{site.prodNameWindows}} the hard way. | no |
| Datastore          | {{site.prodNameWindows}} datastore type [`kubernetes` or `etcdv3`]  for reading endpoints and policy information. | kubernetes |
| EtcdEndpoints      | Comma-delimited list of etcd connection endpoints. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379`. Valid only if `Datastore` is set to `etcdv3`. | "" |
| ServiceCidr        | Service IP range of the Kubernetes cluster. Not required for managed Kubernetes cluster (for example, EKS). | 10.96.0.0/12 |
| DNSServerIPs       | Comma-delimited list of DNS service IPs used by Windows pod. Not required for managed Kubernetes cluster (for example, EKS) | 10.96.0.10 |

Congratulations! You now have a Kubernetes cluster with {{site.prodNameWindows}} and a Linux control node. 

### Next steps

You can now use the {{site.prodname}} Linux-based docs site for your documentation. Before you continue, review the [Limitations and known issues]({{site.baseurl}}/getting-started/windows-calico/limitations) to understand the features (and sections of documentation) that do not apply to Windows. 
