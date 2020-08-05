---
title: Install Calico for Windows 
description: Install Calico for Windows to enable a workload-to-workload Zero Trust model that protects modern business and legacy applications.
canonical_url: '/getting-started/windows-calico/standard'
---

### Big picture

Install {{site.prodNameWindows}} on Kubernetes clusters.

### Value

Extend your Kubernetes deployment to Windows environments.

### Before you begin

**Required**

- Install and configure [calicoctl]({{site.baseurl}}/getting-started/clis/calicoctl/)
- Linux and Windows nodes [meet requirements]({{site.baseurl}}/getting-started/windows-calico/requirements)
- Download {{site.prodNameWindows}} and Kubernetes binaries to each Windows nodes to prepare for install:

  On each of your Windows nodes, download and run {{site.prodNameWindows}} installation scripts:

  ```
  Invoke-WebRequest https://github.com/projectcalico/calico/releases/download/v3.16.0/install-calico-windows.ps1 -OutFile c:\install-calico-windows.ps1
  c:\install-calico-windows.ps1 -DownloadOnly yes -KubeVersion <your Kubernetes version>
  ```
  cd into `c:\CalicoWindows`, you will see the calico-node.exe binary, install scripts, and other files.

### How to

Because the Kubernetes and {{site.prodname}} control components do not run on Windows yet, a hybrid Linux/Windows cluster is required. First you create a Linux cluster for {{site.prodname}} components, then you join Windows nodes to the Linux cluster.

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:BGP,Datastore:etcd|kdd' %}     
%>

**Kubernetes**
1. [Create a Linux cluster](#create-a-linux-cluster)
1. [Ensure pods run on the correct nodes](#ensure-pods-run-on-the-correct-nodes)
1. [Prepare Windows nodes to join the Linux cluster](#prepare-windows-nodes-to-join-the-linux-cluster)

**{{site.prodname}}**
1. [Install Calico on Linux control and worker nodes](#install-calico-on-linux-control-and-worker-nodes)
1. [Install Calico and Kubernetes on Windows nodes](#install-calico-and-kubernetes-on-windows-nodes)

#### Create a Linux cluster

There are many ways to create a Linux Kubernetes cluster. The Tigera team regularly tests {{ site.prodNameWindows }} with `kubeadm`.

#### Ensure pods run on the correct nodes

A primary issue of running a hybrid Kubernetes cluster is that many Kubernetes manifests do not specify a **node selector** to restrict where their pods can run. For example, `kubeadm` installs `kube-proxy` (Kubernetes per-host NAT daemon) using a DaemonSet that does not include a node selector. This means that the kube-proxy pod, which only supports Linux, will be scheduled to both Linux and Windows nodes. Services/pods that should run only on Linux nodes (such as the `kube-proxy` DaemonSet) should be started with a node selector to avoid attempting to schedule them to Windows nodes.

To get around this for `kube-proxy`:

1. Use `kubectl` to retrieve the DaemonSet.

   ```
    kubectl get ds kube-proxy -n kube-system -o yaml > kube-proxy.yaml
   ```
1. Modify the `kube-proxy.yaml` file to include a node selector that selects only Linux nodes:

   ```
   spec:
   template:
   ...
   spec:
   nodeSelector:
   beta.kubernetes.io/os: linux
   containers:
   ```
1. Apply the updated manifest.

   ```
   kubectl apply -f kube-proxy.yaml
   ``` 
   
A similar change may be needed for other Kubernetes services (such as `kube-dns` or `core-dns`).

#### Prepare Windows nodes to join the Linux cluster

On each Windows node, follow these step to prepare the Windows nodes to your the Kubernetes cluster. {% include open-new-window.html text='Microsoft guide' url='https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/joining-windows-workers' %}.

**Step 1: Configure kubelet**

`kubelet` must be configured to use CNI networking by setting the following command line arguments:

- `--network-plugin=cni`
- `--cni-bin-dir=<directory for CNI binaries>`
- `--cni-conf-dir=<directory for CNI configuration>`

The settings for the latter two arguments are required by the {{site.prodname}} installer in the next stage.

The following kubelet settings are also important:

- `--hostname-override` can be set to $(hostname) to match {{site.prodname}}'s default. `kubelet` and {{site.prodname}} must agree on the host/nodename; if your network environment results in hostnames that vary over time you should set the hostname override to a static value per host and update {{site.prodname}}'s nodename accordingly.
- `--node-ip` should be used to explicitly set the IP that kubelet reports to the API server for the node. We recommend setting this to the host's main network adapter's IP since we've seen kubelet incorrectly use an IP assigned to a HNS bridge device rather than the host's network adapter.
- Because of a Windows networking limitation, if using {{site.prodname}} IPAM, --max-pods should be set to, at most, the IPAM block size of the IP pool in use minus 4:

  | **IP pool block size** | **Max pods**   |
  | ---------------------- | -------------- |
  | /n                     | 2^/32-n^  -  4 |
  | /24                    | 252            |
  | /25                    | 124            |
  | /26 (default)          | 60             |
  | /27                    | 28             |
  | /28                    | 12             |
  | /29                    | 4              |
  | /30 or above           | Cannot be used |

In addition, it's important that `kubelet` is started after the vSwitch has been created, which happens when {{site.prodname}}initializes the dataplane. Otherwise, `kubelet` can be disconnected for the API server when the vSwitch is created.

**AWS users**: If using the AWS cloud provider, you should add the following argument to the `kubelet`: 

--hostname-override=<aws instance private DNS name> (and set the {{site.prodname}} nodename variable to match). In addition, you should add KubernetesCluster=<cluster-name> as a tag when creating your Windows instance.

**As a quickstart**, the {{site.prodname}} package includes a sample script at `CalicoWindows\kubernetes\kubelet-service.ps1` that:

- Waits for {{site.prodname}} to initialise the vSwitch
- Atarts `kubelet` with
  - CNI enabled
  - --hostname-override set to match {{site.prodname}}'s nodename
  - --node-ip set to the IP of the default vEthernet device

See the README in the same directory for more details. Feel free to modify the script to adjust other `kubelet` parameters.

>**Note**: The script will pause at the first stage until {{site.prodname}} is installed by following the instructions in the next section.
{: .alert .alert-info}

**Step 2: Configure kube-proxy**

`kube-proxy` must be configured as follows:

- With the correct HNS network name used by the active CNI plugin. kube-proxy reads the HNS network name from an environment variable KUBE_NETWORK
  - With default configuration, {{site.prodname}} uses network name "{{site.prodname}}"
- For VXLAN, with the source VIP for the pod subnet allocated to the node. This is the IP that kube-proxy uses when it does SNAT for a NodePort. For {{site.prodname}}, the source VIP should be the second IP address in the subnet chosen for the host. For example, if {{site.prodname}} chooses an IP block 10.0.0.0/26 then the source VIP should be 10.0.0.2. The script below will automatically wait for the block to be chosen and configure kube-proxy accordingly.
- For {{site.prodname}} policy to function correctly with Kubernetes services, the WinDSR feature gate must be enabled. This requires Windows 1903 build 18317 or greater and Kubernetes v1.14 or greater.

kube-proxy should be started via a script that waits for the Calico HNS network to be provisioned. The {{site.prodname}} package contains a suitable script for use with {{site.prodname}} networking at `CalicoWindows\kubernetes\kube-proxy-service.ps1`. The script:

- Waits for {{site.prodname}} to initialise the vSwitch.
- Calculates the correct source VIP for the local subnet.
- Starts kube-proxy with the correct feature gates and hostname to work with {{site.prodname}}.

See the README in the same directory for more details. Feel free to modify the script to
adjust other kube-proxy parameters.

>**Note**: The script will pause at the first stage until {{site.prodname}} is installed by following the instructions in the next section.

#### Install Calico on Linux control and worker nodes

1. Modify VXLAN as described in [Customize the manifests]({{site.baseurl}}/getting-started/kubernetes/installation/config-options) guide. Note the following:
   - Windows can support only a single type of IP pool so it is important that you use only a single VXLAN IP pool in this mode.
   - Windows supports only VXLAN on port 4789 and VSID >=4096. {{site.prodname}}'s default (on Linux and Windows) is to use port 4789 and VSID 4096.

1. Apply the manifest using `calicoctl`, and verify that you have a single pool with `VXLANMODE Always`. 

  ```
  $ calicoctl get ippool -o wide
  ```
#### Install Calico and Kubernetes on Windows nodes

Follow the steps below on each Windows node to install Kubernetes and {{site.prodname}}:

1. If using a non-{{site.prodname}} network plugin for networking, install and verify it now. 
1. Edit the install configuration file, `config.ps1` as follows:

| **Set this variable...** | To...                   |
| ----------- | ----------------------------------------------------- |
| $env:KUBE_NETWORK | CNI plugin you plan to use. For {{site.prodname}}, set the variable to `{{site.prodname}}.*` |
| $env:CALICO_NETWORKING_BACKEND | `vxlan` or `none` (if using a non-{{site.prodname}} CNI plugin). |
| $env:CNI_ variables | Location of your Kubernetes installation. |
| $env:K8S_SERVICE_CIDR | Your Kubernetes service cluster IP CIDR. |
| $env:CALICO_DATASTORE_TYPE | {{site.prodname}} datastore you want to use. |
| $env:KUBECONFIG | Location of the kubeconfig file {{site.prodname}} should use to access the Kubernetes API server. To set up a secure kubeconfig with the correct permissions for {{site.prodNameWindows}}, see [Create a cluster role]({{site.baseurl}}/getting-started/windows-calico/cluster-roles) and kubeconfig for {{site.prodNameWindows}}. |
| $env:ETCD_ parameters | etcd3 datastore parameters. **Note**: Because of a limitation of the Windows dataplane, a Kubernetes service ClusterIP cannot be used for the etcd endpoint (the host compartment cannot reach Kubernetes services). |
| $env:NODENAME | Hostname used by kubelet. The default uses the node's hostname. **Note**: If you are using the sample kubelet start-up script from the {{site.prodname}} package, kubelet is started with a hostname override that forces it to use this value. |
|  | For AWS to work properly, kubelet should use the node's internal domain name for the AWS integration. |

1. Run the installer.
  
  - Change directory to the location that you unpacked the archive. For example:

  ```
  PS C:\... > cd c:\CalicoWindows
  ```
  - Run the install script:

  ```
  PS C:\... > .\install-calico.ps1
  ```

  > **Note**: The installer initializes the Windows vSwitch, which can cause a short connectivity outage as the networking stack is reconfigured. After running that command, you may need to:
- Reconnect to your remote desktop session.
- Restart `kubelet` and `kube-proxy` if they were already running.
- If you haven't started `kubelet` and `kube-proxy` already, you should do so now. The quickstart scripts provided in the {{site.prodname}} package provide an easy way to do this. {{site.prodname}} requires `kubelet` to be running to complete its per-node configuration (since Kubelet creates the Kubernetes Node resource).
{: .alert .alert-info}

  > **Note**: After you run the installer, do not move the directory because the service registration refers to the path of the directory.
{: .alert .alert-info}

### Next steps

- [Configure cluster roles]({{site.baseurl}}/getting-started/windows-calico/cluster-roles)
- [Review network policy limitations in Windows]({{site.baseurl}}/getting-started/windows-calico/limitations)
