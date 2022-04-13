---
title: Quickstart
description: Install Calico for Windows on a Kubernetes cluster for testing or development.
canonical_url: '/getting-started/windows-calico/quickstart'
---

### Big picture

Install {{site.prodnameWindows}} on your Kubernetes cluster in approximately 5 minutes.

### Concepts

{{site.prodnameWindows}} is a hybrid implementation that requires a Linux cluster for {{site.prodname}} components and Linux workloads, and Windows nodes for Windows workloads.

### Before you begin

Review the [Linux requirements]({{site.baseurl}}/getting-started/kubernetes/requirements) and the [{{site.prodnameWindows}} requirements]({{site.baseurl}}/getting-started/windows-calico/kubernetes/requirements).

Before beginning the quickstart, setup a {{site.prodname}} cluster on Linux nodes and provision Windows machines.

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

#### Install {{site.prodnameWindows}} using DaemonSet

> **Note**: This installation method is a tech preview and should not be used for production clusters. Upgrades a tech preview version of this
> installation method to the GA version might not be seamless.
{: .alert .alert-info}

In addition to the [{{site.prodnameWindows}} requirements]({{site.baseurl}}/getting-started/windows-calico/kubernetes/requirements), this installation method uses [Windows HostProcess containers](https://kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/) which requires:

- Kubernetes v1.22+
- HostProcess containers support enabled: for v1.22, HostProcess containers support has to be [enabled](https://v1-22.docs.kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/#before-you-begin-version-check). For Kubernetes v1.23+, HostProcess containers are enabled by default.
- ContainerD 1.6.1

Before beginning, ensure that the Windows nodes have [joined the cluster](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/adding-windows-nodes/#joining-a-windows-worker-node).

1. Download the {{site.prodnameWindows}} installation manifest.

   ```bash
   curl {{ "/manifests/calico-windows-vxlan.yaml" | absolute_url }} -O calico-windows.yaml
   ```

1. Get the cluster's Kubernetes API server host and port.

   {% include content/kube-apiserver-host-port.md %}

1. Edit the `calico-windows-config` configmap in the downloaded manifest and ensure the required variables are correct for your cluster:
   - `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`: The Kubernetes API server host and port (discovered in the previous step).
   - `K8S_SERVICE_CIDR`: The Kubernetes service clusterIP range configured in your cluster. This must match the service-cluster-ip-range used by kube-apiserver.
   - `CNI_BIN_DIR`: Path where Calico CNI binaries will be installed. The this must match the CNI bin values in the ContainerD service configuration.
   - `CNI_CONF_DIR`: Path where Calico CNI configuration will be installed. this must match the CNI conf values in the ContainerD service configuration.
   - `DNS_NAME_SERVERS`: The DNS nameservers that will be used in the CNI configuration.

1. Apply the {{site.prodnameWindows}} installation manifest.

   ```bash
   kubectl create -f calico-windows.yaml
   ```

1. Monitor the installation.

   ```bash
   kubectl logs -f -n calico-system -l k8s-app=calico-node-windows -c install
   ```

   Once the log `Calico for Windows installed` appears, installation is complete.
   Next, the {{site.prodnameWindows}} services are started in separate containers:

   ```bash
   kubectl logs -f -n calico-system -l k8s-app=calico-node-windows -c node
   kubectl logs -f -n calico-system -l k8s-app=calico-node-windows -c felix
   ```

1. Install kube-proxy

   Depending on your platform, you may already have kube-proxy running. If it is not, you must install and run kube-proxy on each of the Windows nodes
   in your cluster.


#### Install {{site.prodnameWindows}} manually

The following steps install a Kubernetes cluster on a single Windows node, with a Linux control node.

- **Kubernetes VXLAN**

  The geeky details of what you get by default:
  {% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

- **Kubernetes BGP**

  The geeky details of what you get by default:
  {% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:No,Routing:BGP,Datastore:Kubernetes' %}

- **EKS**

  The geeky details of what you get by default:
  {% include geek-details.html details='Policy:Calico,IPAM:AWS,CNI:AWS,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

- **AKS**

  The geeky details of what you get by default:
  {% include geek-details.html details='Policy:Calico,IPAM:Azure,CNI:Azure,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}


{% tabs %}
  <label:Kubernetes VXLAN,active:true>
  <%

1. Ensure that BGP is disabled since you're using VXLAN.
   If you installed Calico using operator, you can do this by:

   ```bash
   kubectl patch installation default --type=merge -p '{"spec": {"calicoNetwork": {"bgp": "Disabled"}}}'
   ```
   If you installed Calico using the manifest from https://projectcalico.docs.tigera.io/manifests/calico-vxlan.yaml then BGP is already disabled.

1. Prepare the directory for Kubernetes files on Windows node.

   ```powershell
   mkdir c:\k
   ```

1. Copy the Kubernetes kubeconfig file from the master node (default, Location $HOME/.kube/config), to **c:\k\config**.

1. Download the PowerShell script, **install-calico-windows.ps1**.

   ```powershell
   Invoke-WebRequest {{ "/scripts/install-calico-windows.ps1" | absolute_url }} -OutFile c:\install-calico-windows.ps1
   ```

1. Install Calico for Windows for your datastore with using the default parameters or [customize installation parameters]. (#configure-installation-parameters).
   The PowerShell script downloads Calico for Windows release binary, Kubernetes binaries, Windows utilities files, configures Calico for Windows, and starts the Calico service.

   **Kubernetes datastore (default)**

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <your Kubernetes version (e.g. 1.18.6)> `
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> `
                                 -DNSServerIPs <your DNS service IP (default 10.96.0.10)>
   ```

   **etcd datastore**

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <your Kubernetes version (e.g. 1.18.6)> `
                                 -Datastore etcdv3 `
                                 -EtcdEndpoints <your etcd endpoint ip> `
                                 -EtcdTlsSecretName <your etcd TLS secret name in calico-system namespace> (default no etcd TLS secret is used) `
                                 -EtcdKey <path to key file> (default not using TLS) `
                                 -EtcdCert <path to cert file> (default not using TLS) `
                                 -EtcdCaCert <path to ca cert file> (default not using TLS) `
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> `
                                 -DNSServerIPs <your DNS server IPs (default 10.96.0.10)>
   ```

   > **Note**: You do not need to pass a parameter if the default value of the parameter is correct for your cluster.
   {: .alert .alert-info}

   > **Note**: If your Windows nodes have multiple network adapters, you can configure the one used for VXLAN by editing `VXLAN_ADAPTER` in `{{site.rootDirWindows}}\config.ps1`, then restarting {{site.prodnameWindows}}.
   {: .alert .alert-info}

1. Verify that the {{site.prodname}} services are running.

   ```powershell
   Get-Service -Name CalicoNode
   Get-Service -Name CalicoFelix
   ```

1. Install and start kubelet/kube-proxy service. Execute following PowerShell script/commands.

   ```powershell
   {{site.rootDirWindows}}\kubernetes\install-kube-services.ps1
   Start-Service -Name kubelet
   Start-Service -Name kube-proxy
   ```
1. Verify kubelet/kube-proxy services are running.

   ```powershell
   Get-Service -Name kubelet
   Get-Service -Name kube-proxy
   ```

%>

  <label:Kubernetes BGP>
  <%

1. Enable BGP service on Windows node (instead of VXLAN).
   Install the RemoteAccess service using the following Powershell commands:

   ```powershell
   Install-WindowsFeature RemoteAccess
   Install-WindowsFeature RSAT-RemoteAccess-PowerShell
   Install-WindowsFeature Routing
   ```

   Then restart the computer:

   ```powershell
   Restart-Computer -Force
   ```

   before running:

   ```powershell
   Install-RemoteAccess -VpnType RoutingOnly
   ```
   Sometimes the remote access service fails to start automatically after install. To make sure it is running, execute the following command:

   ```powershell
   Start-Service RemoteAccess
   ```

1. Prepare the directory for Kubernetes files on Windows node.

   ```powershell
   mkdir c:\k
   ```

1. Copy the Kubernetes kubeconfig file from the master node (default, Location $HOME/.kube/config), to **c:\k\config**.

1. Download the PowerShell script, **install-calico-windows.ps1**.

   ```powershell
   Invoke-WebRequest {{ "/scripts/install-calico-windows.ps1" | absolute_url }} -OutFile c:\install-calico-windows.ps1
   ```

1. Install Calico for Windows for your datastore with using the default parameters or [customize installation parameters]. (#configure-installation-parameters).
   The PowerShell script downloads Calico for Windows release binary, Kubernetes binaries, Windows utilities files, configures Calico for Windows, and starts the Calico service.

   You do not need to pass a parameter if the default value of the parameter is correct for your cluster.

   **Kubernetes datastore (default)**

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <your Kubernetes version (e.g. 1.18.6)> `
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> `
                                 -DNSServerIPs <your DNS service IP (default 10.96.0.10)>
   ```

   **etcd datastore**

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <your Kubernetes version (e.g. 1.18.6)> `
                                 -Datastore etcdv3 `
                                 -EtcdEndpoints <your etcd endpoint ip> `
                                 -EtcdTlsSecretName <your etcd TLS secret name in calico-system namespace> (default no etcd TLS secret is used) `
                                 -EtcdKey <path to key file> (default not using TLS) `
                                 -EtcdCert <path to cert file> (default not using TLS) `
                                 -EtcdCaCert <path to ca cert file> (default not using TLS) `
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> `
                                 -DNSServerIPs <your DNS server IPs (default 10.96.0.10)>
   ```

   > **Note**: You do not need to pass a parameter if the default value of the parameter is correct for your cluster.
   {: .alert .alert-info}


1. Verify that the {{site.prodname}} services are running.

   ```powershell
   Get-Service -Name CalicoNode
   Get-Service -Name CalicoFelix
   ```

1. Install and start kubelet/kube-proxy service. Execute following PowerShell script/commands.

   ```powershell
   {{site.rootDirWindows}}\kubernetes\install-kube-services.ps1
   Start-Service -Name kubelet
   Start-Service -Name kube-proxy
   ```
1. Verify kubelet/kube-proxy services are running.

   ```powershell
   Get-Service -Name kubelet
   Get-Service -Name kube-proxy
   ```

%>

  <label:EKS>
  <%
1. Ensure that a Windows instance role has permissions to get `namespaces` and to get `secrets` in the calico-system namespace (or kube-system namespace if you are using a non operator-managed {{site.prodname}} installation.)
   One way to do this is by running the following comands to install the required permissions temporarily. Before running the commands, replace `<eks_node_name>` with the Kubernetes node name of the EKS Windows node, for example `ip-192-168-42-34.us-west-2.compute.internal`.
   > **Note**: If you are using a non operator-managed {{site.prodname}} installation, replace the namespace `calico-system` with `kube-system` in the commands below.
   {: .alert .alert-info}
   ```bash
   kubectl create clusterrole calico-install-ns --verb=get --resource=namespace
   kubectl create clusterrolebinding calico-install-ns --clusterrole=calico-install-ns --user=system:node:<eks_node_name>
   kubectl create role calico-install-token --verb=get,list --resource=secrets --namespace calico-system
   kubectl create rolebinding calico-install-token --role=calico-install-token --user=system:node:<eks_node_name> --namespace calico-system
   ```

1. Prepare the directory for Kubernetes files on the Windows node.

   ```powershell
   mkdir c:\k
   ```

1. [Install kubectl](https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html#windows){:target="_blank"} and move the kubectl binary to **c:\k**.

1. Download the PowerShell script, **install-calico-windows.ps1**.

   ```powershell
   Invoke-WebRequest {{site.url}}/scripts/install-calico-windows.ps1 -OutFile c:\install-calico-windows.ps1
   ```

1. Install Calico for Windows for your datastore with using the default parameters or [customize installation parameters]. (#configure-installation-parameters).
   The PowerShell script downloads Calico for Windows release binary, Kubernetes binaries, Windows utilities files, configures Calico for Windows, and starts the Calico service.

   You do not need to pass a parameter if the default value of the parameter is correct for your cluster.

   **Kubernetes datastore (default)**

   ```powershell
   c:\install-calico-windows.ps1 -ServiceCidr <your service cidr (default 10.96.0.0/12)> `
                                 -DNSServerIPs <your DNS service IP (default 10.96.0.10)>
   ```

   **etcd datastore**

   ```powershell
   c:\install-calico-windows.ps1 -Datastore etcdv3 `
                                 -EtcdEndpoints <your etcd endpoint ip> `
                                 -ServiceCidr <your service cidr (default 10.96.0.0/12)> `
                                 -DNSServerIPs <your DNS server IPs (default 10.96.0.10)>
   ```

   > **Note**: You do not need to pass a parameter if the default value of the parameter is correct for your cluster.
   {: .alert .alert-info}


1. Verify that the {{site.prodname}} services are running.

   ```powershell
   Get-Service -Name CalicoNode
   Get-Service -Name CalicoFelix
   ```

1. Verify kubelet and kube-proxy services are running.

   ```powershell
   Get-Service -Name kubelet
   Get-Service -Name kube-proxy
   ```

1. If you installed temporary RBAC in the first step, remove the permissions by running the following commands.
   > **Note**: If you are using a non operator-managed {{site.prodname}} installation, replace the namespace `calico-system` with `kube-system` in the commands below.
   {: .alert .alert-info}
   ```bash
   kubectl delete clusterrolebinding calico-install-ns
   kubectl delete clusterrole calico-install-ns
   kubectl delete rolebinding calico-install-token --namespace calico-system
   kubectl delete role calico-install-token --namespace calico-system
   ```
%>

<label:AKS>
<%

1. Register the `EnableAKSWindowsCalico` feature flag with the following Azure CLI commad.

   ```bash
   az feature register --namespace "Microsoft.ContainerService" --name "EnableAKSWindowsCalico"
   ```

1. Wait until the `EnableAKSWindowsCalico` feature flag is registered successfully. Execute following CLI command to get current status of the feature.

   ```bash
   az feature list -o table --query "[?contains(name, 'Microsoft.ContainerService/EnableAKSWindowsCalico')].{Name:name,State:properties.state}"
   ```

   Move to next step if the output from above command matches the following output.
   ```bash
   Name                                               State
   -------------------------------------------------  ----------
   Microsoft.ContainerService/EnableAKSWindowsCalico  Registered
   ```

1. Refresh the registration of the `Microsoft.ContainerService` resource provider. Execute the following command.

   ```bash
   az provider register --namespace Microsoft.ContainerService
   ```

1. Create the AKS cluster with these settings: `network-plugin` to `azure`, and `network-policy` to `calico`. For example,

   ```bash
   az group create -n $your-resource-group -l $your-region
   az aks create \
    --resource-group $your-resource-group \
    --name $your-cluster-name \
    --node-count 1 \
    --enable-addons monitoring \
    --windows-admin-username azureuser \
    --windows-admin-password $your-windows-password \
    --kubernetes-version 1.20.2 \
    --vm-set-type VirtualMachineScaleSets \
    --service-principal $your-service-principal \
    --client-secret $your-client-secret \
    --load-balancer-sku standard \
    --node-vm-size Standard_D2s_v3 \
    --network-plugin azure \
    --network-policy calico
   ```

1. Add a Windows node pool. For example,

   ```bash
   az aks nodepool add \
    --resource-group $your-resource-group \
    --cluster-name $your-cluster-name \
    --os-type Windows \
    --name $your-windows-node-pool-name \
    --node-count 1 \
    --kubernetes-version 1.20.2 \
    --node-vm-size Standard_D2s_v3
   ```
%>
{% endtabs %}

#### Configure installation parameters

| **Parameter Name** | **Description**                                           | **Default** |
| ------------------ | --------------------------------------------------------- |-------------|
| KubeVersion        | Version of Kubernetes binaries to use. If the value is an empty string (default), the {{site.prodnameWindows}} installation script does not download Kubernetes binaries and run Kubernetes service. Use the default for managed public cloud. | "" |
| DownloadOnly       | Download without installing {{site.prodnameWindows}}. Set to `yes` to manually install and configure {{site.prodnameWindows}}. For example, {{site.prodnameWindows}} the hard way. | no |
| Datastore          | {{site.prodnameWindows}} datastore type [`kubernetes` or `etcdv3`] for reading endpoints and policy information. | kubernetes |
| EtcdEndpoints      | Comma-delimited list of etcd connection endpoints. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379`. Valid only if `Datastore` is set to `etcdv3`. | "" |
| EtcdTlsSecretName  | Name of a secret in `calico-system` namespace which contains `etcd-key`, `etcd-cert`, `etcd-ca` for automatically configuring TLS. Either use this or parameters `EtcdKey`, `EtcdCert`, `EtcdCaCert` below. Note: If you are not using operator-based installation, use namespace `kube-system`. | "" |
| EtcdKey            | Path to key file for etcd TLS connection. | "" |
| EtcdCert           | Path to certificate file for etcd TLS connection. | "" |
| EtcdCaCert         | Path to CA certificate file for etcd TLS connection. | "" |
| ServiceCidr        | Service IP range of the Kubernetes cluster. Not required for most managed Kubernetes clusters. Note: EKS has non-default value. | 10.96.0.0/12 |
| DNSServerIPs       | Comma-delimited list of DNS service IPs used by Windows pod. Not required for most managed Kubernetes clusters. Note: EKS has a non-default value. | 10.96.0.10 |
| CalicoBackend      | Calico backend network type (`vxlan` or `bgp`). If the value is an empty string (default), backend network type is auto detected. | "" |

Congratulations! You now have a Kubernetes cluster with {{site.prodnameWindows}} and a Linux control node.

### Next steps

You can now use the {{site.prodname}} Linux-based docs site for your documentation. Before you continue, review the [Limitations and known issues]({{site.baseurl}}/getting-started/windows-calico/limitations) to understand the features (and sections of documentation) that do not apply to Windows.
