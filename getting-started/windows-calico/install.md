---
title: Install Calico for Windows
description: Install Calico for Windows and enable a workload-to-workload Zero Trust model that protects modern
business and legacy applications.
canonical_url: 
---

### Big picture

Using {{ site.prodNameWindows }} requires a configuring a hybrid Linux/Windows Kubernetes cluster. 

### Concepts

Because the Kubernetes and {{site.prodname}} control components do not yet run on Windows, a hybrid Linux/Windows cluster is required. First you create a Linux cluster for {{site.prodname}} components, then you add Windows nodes to the Linux cluster.

### Before you begin

**Required**

- [calicoctl is installed and configured]({{site.baseurl}}/getting-started/clis/calicoctl/)
- You have [determined your network plugin]({site.baseurl}}/getting-started/windows-calico/determine-networking) and Linux and Windows nodes [meet requirements]({site.baseurl}}/getting-started/windows-calico/requirements)
- Copy the .zip files (provided by your support representative) to each Windows nodes to prepare for install:

  On each of your Windows nodes, copy the release .zip archive, **tigera-calico-windows-<version>.zip** and unpack it. For example, using PowerShell:

  ```
  PS C:\... > Expand-Archive tigera-calico-windows-vx.y.z.zip C:\
  ```
  After expanding the archive, c:\TigeraCalico you will see the tigera-calico.exe binary, install scripts, and other files.

### How to

Because the Kubernetes and {{site.prodname}} control components do not yet run on Windows, a hybrid Linux/Windows cluster is required. First you create a Linux cluster for {{site.prodname}} components, then you add Windows nodes to the Linux cluster.

**Kubernetes**
- [Create a Linux cluster](#create-a-linux-cluster)
- [Ensure pods run on the correct nodes](#ensure-pods-run-on-the-correct-nodes)
- [Prepare Windows nodes to join the Kubernetes cluster](#prepare-windows-nodes-to-join-the-kubernetes-cluster)

**Calico**
- [Install Calico on Linux master and worker nodes](#install-calico-on-linux-master-and-worker-nodes)
- [Install Calico and Kubernetes on Windows nodes](#install-calico-and-kubernetes-on-windows-nodes)

**Post install tasks**
- [Create a Windows cluster role](#create-a-windows-cluster-role)
- [Manage Calico services](#start-stop-and-change-calico-services)

#### Create a Linux cluster

There are many ways to create a Linux Kubernetes cluster. The Tigera team regularly tests {{ site.prodNameWindows }} with `kubeadm`.

#### Ensure pods run on the correct nodes

A primary issue of running a hybrid Kubernetes cluster is that many Kubernetes manifests do not specify a **node selector** to restrict where their pods can run. For example, `kubeadm` installs `kube-proxy` (Kubernetes per-host NAT daemon) using a DaemonSet that does not include a node selector. This means that the kube-proxy pod, which only supports Linux, will be scheduled to both Linux and Windows nodes. Services/pods that should run only on Linux nodes (such as the `kube-proxy` DaemonSet) should be started with a node selector to avoid attempting to schedule them to Windows nodes.
{: .alert .alert-info}

To get around this for `kube-proxy`:

- Use `kubectl` to retrieve the DaemonSet:

  ```
  kubectl get ds kube-proxy -n kube-system -o yaml > kube-proxy.yaml
  ```
- Modify the `kube-proxy.yaml` file to include a node selector that selects only Linux nodes:

  ```
   spec:
   template:
   ...
   spec:
   nodeSelector:
   beta.kubernetes.io/os: linux
   containers:
   ```
- Apply the updated manifest:

  ```
  kubectl apply -f kube-proxy.yaml
  ``` 
A similar change may be needed for other Kubernetes services (such as `kube-dns` or `core-dns`).

#### Prepare Windows nodes to join the Kubernetes cluster

**If you are using non-{{site.prodname}} networking**

  On each Windows node, follow these step to prepare and join the Windows nodes to your the Kubernetes cluster. {% include open-new-window.html text='Microsoft guide' url='https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/joining-windows-workers' %}.

**If you are using {{site.prodname}} networking**

> **Important!**: Do not follow the Microsoft guide (above) to join Windows nodes to the Kubernetes cluster; the steps use scripts that auto-configure CNI plugins as part of Kubernetes startup, and conflicts with the {{site.prodname}} CNI plugin. Instead, follow the steps below.
{: .alert .alert-warning}

**On each Windows node in the cluster**:

**Step 1: Install docker**

**AWS users**: AWS provides images with docker pre-installed, such as "Windows 1903 with containers"; if you are using such an image, you can skip this section.

1. Follow the instructions in the Microsoft guide to install docker.
1. After reboot, check the install with:
   
   ```
   docker version
   ```
If you see an error, try manually starting the docker service and its dependencies:

   ```
   PS C:\>Start-Service VMSP
   PS C:\>Start-Service docker
   ```
**Step 2: Install docker base images**

To start most containers on Windows, docker requires a set of base images that match the {% include open-new-window.html text='host operating system' url='https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility#matching-container-host-version-with-container-image-versions' %}

To download those images, follow these steps before running or building and containers:

- For the nanoserver base image, for 1903 or 1809, run the following command, replacing <windows version> with, for example, 1903 if you are running Windows Server 1903:
  ```
  PS C:\> docker pull microsoft/nanoserver:<windows version>
  ```  
For an insider preview build of Windows, the images can be found in the {% include open-new-window.html text='nanoserver repo' url='http://mcr.microsoft.com/windows/nanoserver/insider:10.0.18317.1000' %}

  ```
  PS C:\> docker pull mcr.microsoft.com/windows/nanoserver/insider:10.0.18317.1000:<full version>
  ```
Where `<full version>` is the full version and build ID, such as 10.0.18317.1000

Then, retag the image with the expected names:

```
PS C:\> docker tag microsoft/nanoserver:<windows version> `
microsoft/nanoserver:latest
8
PS C:\> docker tag microsoft/nanoserver:<windows version> `
mcr.microsoft.com/windows/nanoserver:latest
```
Next, for the servercore base image:

```
PS C:\> docker pull microsoft/servercore:<windows version>
Or, for insider preview builds,
PS C:\> docker pull mcr.microsoft.com/windows/servercore/insider:<full version>
```
Then, retag the image with the expected names:

```
PS C:\> docker tag microsoft/servercore:<windows version> `
microsoft/servercore:latest
PS C:\> docker tag microsoft/servercore:<windows version> `
mcr.microsoft.com/windows/servercore:latest
```
Next, to create Kubernetes' "pause" base image download the following file to an empty directory:

```
PS C:\> mkdir pause
PS C:\> cd pause
PS C:\> wget -UseBasicParsing -OutFile Dockerfile `
https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile
PS C:\...> docker build -t kubeletwin/pause .
```
Output of `docker images` should now look something like this (where the image IDs may vary):

```
PS C:\k\pause> docker images
REPOSITORY TAG IMAGE ID CREATED SIZE
kubeletwin/pause latest 6364748f4552 9 seconds ago 362MB
microsoft/nanoserver 1803 ff438082af10 2 days ago 361MB
microsoft/nanoserver latest ff438082af10 2 days ago 361MB
mcr.microsoft.com/windows/nanoserver latest ff438082af10 2 days ago 361MB
microsoft/servercore 1803 223b0f64b800 4 weeks ago 4.96GB
microsoft/servercore latest 223b0f64b800 4 weeks ago 4.96GB
mcr.microsoft.com/windows/servercore latest 223b0f64b800 4 weeks ago 4.96GB
```
**Step 3: Set up a Kubernetes base directory**

To set up the Kubernetes directory, follow these steps:

Create the directories that we'll use in the following steps:

```
PS C:\> mkdir c:\k
PS C:\> mkdir c:\k\cni
PS C:\> mkdir c:\k\cni\config
```
Download the Kubernetes binaries and unpack them into C:\k. For example, the Windows v1.15.10 binaries can be found as the kubernetes-node-windows-amd64.tar.gz file under the Node Binaries section of the v1.15.10 Kubernetes changelog.

Your Windows system may have tar.exe pre-installed; if so, the executables can be extracted with:

```
PS ...> tar.exe -xf kubernetes-node-windows-amd64.tar.gz
Then copy the files from .\kubernetes\bin to c:\k:
PS ...> cp .\kubernetes\node\bin\*.exe c:\k
```
If your system does not have tar.exe installed, 7-zip is a freely-available tool that can extract tar archives.

After unpacking the binaries, the c:\k directory should contain `kube-proxy.exe`, `kubeadm.exe`, `kubelet.exe` and `kubectl.exe`.

Copy the Kubernetes kubeconfig/certificate file to c:\k\config. If using kubeadm, the file will have been emitted to /etc/kubernetes/admin.conf on the master.

>**Note**: the admin.conf file contains the administrator credentials for the cluster; using that file provides the simplest configuration. However, for a production cluster, we recommend running with per-node credentials instead.

Test the kubeconfig file by running `kubectl`:

```
PS C:\> $env:KUBECONFIG="C:\k\config"
PS C:\> \k\kubectl.exe version
```
should show the version of the server and no errors. If you see an error, check the `kubeconfig` file was correctly copied.

Download the base CNI plugins to C:\k\cni:

- {% include open-new-window.html text='win-bridge' url='https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/win-bridge.exe' %}
- {% include open-new-window.html text='host-local' url='https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe' %}

For example, you could use:
```
PS C:\> [Net.ServicePointManager]::SecurityProtocol = `
                             [Net.SecurityProtocolType]::Tls12

PS C:\k> Invoke-Webrequest -OutFile "c:\k\cni\win-bridge.exe" -Uri `
"https://github.com/Microsoft/SDN/raw/master/Kubernetes/l2bridge/cni/win-bridge.exe"

PS C:\k> Invoke-Webrequest -OutFile "c:\k\cni\host-local.exe" -Uri `
"https://github.com/Microsoft/SDN/raw/master/Kubernetes/l2bridge/cni/host-local.exe"
…
```
**Step 4: Configure kubelet**

`kubelet` must be configured to use CNI networking by setting the following command line arguments:

- --network-plugin=cni
- --cni-bin-dir=<directory for CNI binaries>
- --cni-conf-dir=<directory for CNI configuration>

The settings for the latter two arguments are required by the {{site.prodname}} installer in the next stage.

The following kubelet settings are also important:

- --hostname-override can be set to $(hostname) to match {{site.prodname}}'s default. `kubelet` and {{site.prodname}} must agree on the host/nodename; if your network environment results in hostnames that vary over time you should set the hostname override to a static value per host and update {{site.prodname}}'s nodename accordingly.
- --node-ip should be used to explicitly set the IP that kubelet reports to the API server for the node. We recommend setting this to the host's main network adapter's IP since we've seen kubelet incorrectly use an IP assigned to a HNS bridge device rather than the host's network adapter.
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

**As a quickstart**, the {{site.prodname}} package includes a sample script at `TigeraCalico\kubernetes\start-kubelet.ps1` that:

- Waits for {{site.prodname}} to initialise the vSwitch
- Atarts `kubelet` with
  - CNI enabled
  - --hostname-override set to match {{site.prodname}}'s nodename
  - --node-ip set to the IP of the default vEthernet device

See the README in the same directory for more details. Feel free to modify the script to adjust other `kubelet` parameters.

>**Note**: The script will pause at the first stage until {{site.prodname}} is installed by following the instructions in the next section.
{: .alert .alert-info}

**Step 7: Configure kube-proxy**

`kube-proxy` must be configured as follows:

- With the correct HNS network name used by the active CNI plugin. kube-proxy
reads the HNS network name from an environment variable KUBE_NETWORK
  - With default configuration, {{site.prodname}} uses network name "{{site.prodname}}"
  - With default configuration, flannel host gateway uses network name "cbr0"
- For VXLAN, with the source VIP for the pod subnet allocated to the node. This is the IP that kube-proxy will use when it does SNAT for a NodePort. For {{site.prodname}}, the source VIP should be the second IP address in the subnet chosen for the host. For example, if {{site.prodname}} chooses an IP block 10.0.0.0/26 then the source VIP should be 10.0.0.2. The script below will automatically wait for the block to be chosen and configure kube-proxy accordingly.
- For {{site.prodname}} policy to function correctly with Kubernetes services, the WinDSR feature gate must be enabled. This requires Windows 1903 build 18317 or greater and Kubernetes v1.14 or greater.

Because {{site.prodname}} BGP networking creates the HNS network on demand when the first pod is networked on a host, kube-proxy should be started via a script that waits for the network to be provisioned. The {{site.prodname}} package contains a suitable script for use with {{site.prodname}} networking at `TigeraCalico\kubernetes\start-kube-proxy.ps1`. The script:

- Waits for {{site.prodname}} to initialise the vSwitch.
- Calculates the correct source VIP for the local subnet.
- Starts kube-proxy with the correct feature gates and hostname to work with {{site.prodname}}.

See the README in the same directory for more details. Feel free to modify the script to
adjust other kube-proxy parameters.

>**Note**: The script will pause at the first stage until {{site.prodname}} is installed by following the instructions in the next section.

#### Install {{site.prodname}} on Linux master and worker nodes

Select instructions for BGP or VXLAN in this section.

**If using {{site.prodname}} BGP networking** 

1. [Install {{site.prodname}}for policy and networking]({{site.baseurl}}//getting-started/kubernetes/self-managed-onprem/) for etcd or kdd.
1. Disable the default {{site.prodname}} IP-in-IP networking (which is not compatible with Windows), by modifying the {{site.prodname}} manifest, and setting the `CALICO_IPV4POOL_IPIP` environment variable to "Never" before applying the manifest.

   If you do apply the manifest with the incorrect value, changing the manifest and re-applying will have no effect. To adjust the already-created IP pool, you can use `calicoctl` to get it:
   ```
   $ calicoctl get ippool -o yaml > ippool.yaml
   ```
   Then, modify ippool.yaml to set the ipipMode setting and then apply the update:
   ```
   $ calicoctl apply -f ippool.yaml
   ```
**If using {{site.prodname}} VXLAN networking**

1. [Install {{site.prodname}} for policy and networking](h{{site.baseurl}}//getting-started/kubernetes/self-managed-onprem/) for etcd or kdd.
1. Modify VXLAN as described in [Customizing the manifests] guide.

**Note**: Windows can only support a single type of IP pool so it is important that you use only a single VXLAN IP pool in this mode. After applying the manifest using  `calicoctl`,

```
$ calicoctl get ippool -o wide
```
should show a single pool with `VXLANMODE Always`. 

**Notes**:

- Windows only supports VXLAN on port 4789 and VSID >=4096. {{site.prodname}}'s default (on Linux and Windows) is to use port 4789 and VSID 4096.

**If using static routes** follow the "Installing Calico for policy (advanced)" (https://docs.projectcalico.org/getting-started/kubernetes/installation/other) section of the {{site.prodname}} documentation.

#### Install Calico and Kubernetes on each Windows nodes

Follow the steps below on each Windows node to install Kubernetes and {{site.prodname}}:

**If using {{site.prodname}} BGP**

Install the **RemoteAccess** service using the following Powershell commands:
```
PS C:\> Install-WindowsFeature RemoteAccess
PS C:\> Install-WindowsFeature RSAT-RemoteAccess-PowerShell
PS C:\> Install-WindowsFeature Routing
```
Then restart the computer:
```
PS C:\> Restart-Computer -Force
```
before running:
```
PS C:\> Install-RemoteAccess -VpnType RoutingOnly
```
Sometimes the remote access service fails to start automatically after install. To make sure it is running, execute the following command:

```
PS C:\> Start-Service RemoteAccess
```
**If using any non-{{site.prodname}} network plugin**

If using a non-{{site.prodname}} network plugin for networking, it must be installed and verified before installing {{site.prodname}}. 

**Update the install configuration**

**Edit the file config.ps1 as follows**:
- Set $env:KUBE_NETWORK to match the CNI plugin you plan to use. For {{site.prodname}}, set the variable to "{{site.prodname}}.*"
- Set $env:CALICO_NETWORKING_BACKEND to "windows-bgp", "vxlan", or, "none" (if using a non-{{site.prodname}} CNI plugin).
- Set the $env:CNI_ variables to match the location of your Kubernetes installation.
- Set $env:K8S_SERVICE_CIDR to match your Kubernetes service cluster IP CIDR.
- Set $env:CALICO_DATASTORE_TYPE to the {{site.prodname}} datastore you want to use. 
  **Note**: "etcdv3" can only be used with {{site.prodname}} BGP networking. 
- Set $env:KUBECONFIG to the location of the kubeconfig file {{site.prodname}} should use to access the Kubernetes API server. For instructions on setting up a secure kubeconfig with the correct permissions for
{{site.prodNameWindows}}, see "Create a cluster role" and kubeconfig for {{site.prodNameWindows}}.
- If using etcd as the datastore, set the $env:ETCD_ parameters accordingly. 
  **Note**: Due to a limitation of the Windows dataplane, a Kubernetes service ClusterIP cannot be used for the etcd endpoint (the host compartment cannot reach Kubernetes services).
- Set $env:NODENAME to match the hostname used by kubelet. The default is to use the node's hostname.
  **Note**: If you are using the sample kubelet start-up script from the {{site.prodname}} package, kubelet will be started with a hostname override that forces it to use this value.
  **Note**: on AWS, kubelet should use the node's internal domain name for the AWS integration to work properly; $env:NODENAME should be adjusted to match.
- If using {{site.prodname}} BGP networking, the install script will generate a CNI NetConf file from the file cni.conf.template. Certain advanced configuration can be accessed by modifying the template before install.
  **Note**: Prior to Kubernetes v1.13, Kubernetes lacked support for setting the correct DNS configuration on each pod. To work around that limitation, the CNI configuration includes DNS settings that are applied to pods whenever the kubelet fails to pass DNS configuration to the CNI plugin. For v1.13 and above, the DNS configuration of the template is ignored in favour of correct per-pod values learned from the kubelet.

**Run the installer**
  **Note**: After you run the installer, the directory should not be moved because the service registration will refer to the path of the directory.
- Change directory to the location that you unpacked the archive. For example:

  ```
   PS C:\... > cd c:\TigeraCalico
   ```
- Run the install script:

  ```
  PS C:\... > .\install-calico.ps1
  ```
 **Note**: The installer initializes the Windows vSwitch, which can cause a short connectivity outage as the networking stack is reconfigured. After running that command, you may need to:
- Reconnect to your remote desktop session.
- Restart `kubelet` and `kube-proxy` if they were already running.
- If you haven't started `kubelet` and `kube-proxy` already, you should do so now. The quickstart scripts provided in the {{site.prodname}} package provide an easy way to do this. {{site.prodname}} requires `kubelet` to be running to complete its per-node configuration (since Kubelet creates the Kubernetes Node resource).

#### Create cluster role for Windows nodes

Because Kubernetes on Windows cannot run {{site.prodname}} in a pod with an auto-provisioned service account, {{site.prodname}} requires a kubeconfig file to access the API server. This section explains how to create an appropriate service account and then to export the service account token as a kubeconfig file for {{site.prodname}} to use.

>**Note**: The node kubeconfig as used by kubelet does not, in general, have enough permissions to access {{site.prodname}}-specific resources.
{: .alert .alert-info}

Install the cluster-role manifest; this configures a cluster-role named "calico-windows" which will have the correct permissions for {{site.prodNameWindows}}.

On the kubernetes master:

- **If using the Kubernetes API datastore**:

```
$ kubectl apply -f
```
  https://docs.tigera.io/v2.8/getting-started/kubernetes/installation/hos
ted/kubernetes-datastore/policy-only/1.7/win-cluster-role.yaml

- **If using the etcd datastore**:
```
$ kubectl apply -f
```
  https://docs.tigera.io/v2.8/getting-started/kubernetes/installation/hos
ted/policy-only/1.7/win-cluster-role.yaml

Then, to make the kube-config file, you'll need the URL of your Kubernetes API server.

>**Note**: Kubernetes for Windows doesn't support access to services from the host so you must use the address of your server, not the Kubernetes service IP.

Set a variable to the URL of your API server:

```
$ server=https://<server>:<port>
```
Then, find the secret containing the service account token for the calico-windows service account:

```
$ kubectl get secret -n kube-system | grep calico-windows
```
Inspect the output and find the name of the token, store it in a variable:

```
$ name=calico-windows-token-xxxxx
```
Extract the parts of the secret, storing them in variables:

```
$ ca=$(kubectl get secret/$name -o jsonpath='{.data.ca\.crt}' -n
kube-system)

$ token=$(kubectl get secret/$name -o jsonpath='{.data.token}' -n
kube-system | base64 --decode)

$ namespace=$(kubectl get secret/$name -o jsonpath='{.data.namespace}'
-n kube-system | base64 --decode)
```
Then, output the file:

```
cat <<EOF > calico-config
apiVersion: v1
kind: Config
clusters:
- name: kubernetes
cluster:
certificate-authority-data: ${ca}
server: ${server}
contexts:
- name: calico-windows@kubernetes
context:
cluster: kubernetes
namespace: kube-system
user: calico-windows
current-context: calico-windows@kubernetes
users:
- name: calico-windows
user:
token: ${token}
EOF
```
Copy this config file to windows node C:\k\ and set the KUBECONFIG environment variable in `config.ps1` to point to it.

#### Manage Calico services

**Start and stop Calico services**

The `install-calico.ps1` script starts {{site.prodname}} and configures it to start at bootup. Two more scripts are provided to start and stop the {{site.prodname}} services:

- `start-calico.ps1`
- `stop-calico.ps1`

**Update Calico services**

To change the parameters defined in `config.ps1`:

- Run `uninstall-calico.ps1` to remove {{site.prodname}}'s service configuration
- Modify the configuration
- Run `install-calico.ps1`to reinstall {{site.prodname}}.

Since `config.ps1` is imported by the various component startup scripts, additional environment variables can be added, as documented in the [Calico reference guide]({{site.baseurl}}/reference).

**Update service wrapper configuration**

The `nssm` command supports changing a number of configuration options for the {{site.prodname}} services. For example, to adjust the maximum size of the Felix log file before it is rotated: 

```
PS C:\... > nssm set TigeraFelix AppRotateBytes 1048576
```
