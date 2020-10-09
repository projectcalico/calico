---
title: Install an OpenShift 4 cluster on Windows nodes
description: Install Calico on an OpenShift 4 cluster on Windows nodes
canonical_url: '/getting-started/openshift/installation'
---

### Big picture

Install an OpenShift 4 cluster on AWS with {{site.prodname}} on Windows nodes.

### Value

Run Windows workloads on OpenShift 4 with {{site.prodname}}.

### How to

#### Before you begin

- Ensure that your environment meets the {{site.prodname}} [system requirements]({{site.baseurl}}/getting-started/openshift/requirements).

- **If installing on AWS**, ensure that you have {% include open-new-window.html text='configured an AWS account' url='https://docs.openshift.com/container-platform/4.4/installing/installing_aws/installing-aws-account.html' %} appropriate for OpenShift 4,
  and have {% include open-new-window.html text='set up your AWS credentials' url='https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html' %}.
  Note that the OpenShift installer supports a subset of {% include open-new-window.html text='AWS regions' url='https://docs.openshift.com/container-platform/4.4/installing/installing_aws/installing-aws-account.html#installation-aws-regions_installing-aws-account' %}.

- Ensure that you have a {% include open-new-window.html text='RedHat account' url='https://cloud.redhat.com/' %}. A RedHat account is required to obtain the pull secret necessary to provision an OpenShift cluster.

- Ensure that you have installed the OpenShift installer **v4.4 or later** and OpenShift command line interface from {% include open-new-window.html text='cloud.redhat.com' url='https://cloud.redhat.com/openshift/install/aws/installer-provisioned' %}.

- Ensure that you have {% include open-new-window.html text='generated a local SSH private key' url='https://docs.openshift.com/container-platform/4.4/installing/installing_aws/installing-aws-default.html#ssh-agent-using_installing-aws-default' %} and have added it to your ssh-agent

#### Create a configuration file for the OpenShift installer

First, create a staging directory for the installation. This directory will contain the configuration file, along with cluster state files, that OpenShift installer will create:

```
mkdir openshift-tigera-install && cd openshift-tigera-install
```

Now run OpenShift installer to create a default configuration file:

```
openshift-install create install-config
```

> **Note**: Refer to the {% include open-new-window.html text='OpenShift installer documentation' url='https://cloud.redhat.com/openshift/install' %} for more information
> about the installer and any configuration changes required for your platform.
{: .alert .alert-info}

Once the installer has finished, your staging directory will contain the configuration file `install-config.yaml`.

#### Update the configuration file to use {{site.prodname}}

Override the OpenShift networking to use Calico and update the AWS instance types to meet the [system requirements]({{site.baseurl}}/getting-started/openshift/requirements):

```bash
sed -i 's/OpenShiftSDN/Calico/' install-config.yaml
```

#### Generate the install manifests

Now generate the Kubernetes manifests using your configuration file:

```bash
openshift-install create manifests
```

{% include content/install-openshift-manifests.md %}

#### Configure VXLAN

Edit the Installation custom resource manifest `manifests/01-cr-installation.yaml` so that it configures an OpenShift {{site.prodname}} cluster with VXLAN enabled and BGP disabled:


```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  variant: Calico
  calicoNetwork:
    bgp: Disabled
    ipPools:
    - blockSize: 26
      cidr: 10.128.0.0/14
      encapsulation: VXLAN
      natOutgoing: Enabled
      nodeSelector: all()
```

#### Create the cluster

Start the cluster creation with the following command and wait for it to complete.

```bash
openshift-install create cluster
```

Once the above command is complete, you can verify {{site.prodname}} is installed by verifying the components are available with the following command.

```
oc get tigerastatus
```

> **Note**: To get more information, add `-o yaml` to the above command.

Next, install calicoctl and [ensure that strict affinity is true]({{site.baseurl}}/getting-started/windows-calico/quickstart#configure-strict-affinity-for-clusters-using-calico-networking):

#### Add Windows nodes to the cluster

Download the latest [Windows Node Installer
(WNI)](https://github.com/openshift/windows-machine-config-bootstrapper/releases) binaries `wni` and `wmcb.exe` for your OpenShift
version.

Next, determine the AMI id corresponding to Windows Server 1903 (build 18317) or greater. `wni` defaults to using Windows Server 2019 (build 10.0.17763) which does not include WinDSR support.
One way to do this is by searching for AMI's matching the string `Windows_Server-1903-English-Core-ContainersLatest` in the Amazon EC2 console

Next, run `wni` to add a Windows node to your cluster. Replace AMI_ID, AWS_CREDENTIALS_PATH, AWS_KEY_NAME and AWS_PRIVATE_KEY_PATH with your values:

```bash
chmod u+x wni
./wni aws create \
  --image-id AMI_ID \
  --kubeconfig openshift-tigera-install/auth/kubeconfig \
  --credentials AWS_CREDENTIALS_PATH \
  --credential-account default \
  --instance-type m5a.large \
  --ssh-key AWS_KEY_NAME \
  --private-key AWS_PRIVATE_KEY_PATH
```

An example of running the above steps:

```
$ chmod u+x wni
$ ./wni aws create \
>   --kubeconfig openshift-tigera-install/auth/kubeconfig \
>   --credentials ~/.aws/credentials \
>   --credential-account default \
>   --instance-type m5a.large \
>   --ssh-key test-key \
>   --private-key /home/user/.ssh/test-key.pem
2020/10/05 12:52:51 kubeconfig source: /home/user/openshift-tigera-install/auth/kubeconfig
2020/10/05 12:52:59 Added rule with port 5986 to the security groups of your local IP
2020/10/05 12:52:59 Added rule with port 22 to the security groups of your local IP
2020/10/05 12:52:59 Added rule with port 3389 to the security groups of your local IP
2020/10/05 12:52:59 Using existing Security Group: sg-06d1de22807d5dc48
2020/10/05 12:57:30 External IP: 52.35.12.231
2020/10/05 12:57:30 Internal IP: 10.0.90.193
```

#### Install {{site.prodnameWindows}}

1. Prepare directory for Kubernetes files on Windows node.

   ```powershell
   mkdir c:\k
   ```

1. Copy the Kubernetes kubeconfig file from the master node (default, Location $HOME/.kube/config), to the file **c:\k\config**.

1. Download the powershell script, **install-calico-windows.ps1**.

   ```powershell
   Invoke-WebRequest {{ "/scripts/install-calico-windows.ps1" | absolute_url }} -OutFile c:\install-calico-windows.ps1
   ```
1. Run the installation script, replacing the Kubernetes version with the version corresponding to your version of OpenShift. For example, `1.18.3`:

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <kube version> -ServiceCidr 172.30.0.0/16 -DNSServerIPs 172.30.0.10
   ```

1. Re-add the route for the AWS metdata endpoint. First, determine the interface
   index for the `vEthernet (Ethernet 2)` adapter with `Get-NetAdapter`. For
   example:

   ```powershell
   PS C:\> Get-NetAdapter

   Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
   ----                      --------------------                    ------- ------       ----------             ---------
   vEthernet (nat)           Hyper-V Virtual Ethernet Adapter             10 Up           00-15-5D-BA-0F-68        10 Gbps
   Ethernet 2                Amazon Elastic Network Adapter                6 Up           0A-4F-1F-C4-E3-49        25 Gbps
   vEthernet (Ethernet 2)    Hyper-V Virtual Ethernet Adapter #2          15 Up           0A-4F-1F-C4-E3-49        25 Gbps
   ```

   Then, add the route using the interface index:
   ```powershell
   PS C:\> New-NetRoute -DestinationPrefix 169.254.169.254/32 -InterfaceIndex <interface_index>
   ```

#### Configure kubelet

Copy the previously downloaded file `wmcb.exe` and your worker's ignition file (worker.ign) to the Windows node.
To download the worker.ign:

```shell
apiserver=$(oc get po -n  openshift-kube-apiserver -l apiserver=true --no-headers -o custom-columns=":metadata.name" | head -n 1)
oc -n openshift-kube-apiserver exec ${apiserver} -- curl -ks https://localhost:22623/config/worker > worker.ign
```

Remote into the Windows node and configure the kubelet:

```powershell
 ./wmcb.exe initialize-kubelet --ignition-file worker.ign --kubelet-path c:\k\kubelet.exe
```

Next, configure kubelet to use Calico CNI:

```powershell
cp c:\k\config c:\k\kubeconfig
./wmcb.exe configure-cni --cni-dir c:\k\cni --cni-config c:\k\cni\config\10-calico.conf
```

Then, we need to override the pod infra image used by kubelet. This is to ensure
the pod infrastructure image used is using the same base Windows Server OS as
the node. (For more details, see this {% include open-new-window.html text='upstream issue' url='https://github.com/kubernetes/kubernetes/issues/87339' %}.) 

```powershell
docker tag kubeletwin/pause mcr.microsoft.com/k8s/core/pause:1.2.0
```

Lastly, we need to approve the CSR's generated by the kubelet's bootstrapping process. First, view the pending CSR's:

```bash
oc get csr
```

For example:

```
$ oc get csr
NAME        AGE     SIGNERNAME                                    REQUESTOR                                                                   CONDITION
csr-55brx   4m32s   kubernetes.io/kube-apiserver-client-kubelet   system:admin                                                                Approved,Issued
csr-bmnfd   4m30s   kubernetes.io/kubelet-serving                 system:node:ip-10-0-45-102.us-west-2.compute.internal                       Pending
csr-hwl89   5m1s    kubernetes.io/kube-apiserver-client-kubelet   system:serviceaccount:openshift-machine-config-operator:node-bootstrapper   Pending
```

To approve the pending CSR's:

```bash
oc get csr -o name | xargs oc adm certificate approve
```

For example:

```
$ oc get csr -o name | xargs oc adm certificate approve
certificatesigningrequest.certificates.k8s.io/csr-55brx approved
certificatesigningrequest.certificates.k8s.io/csr-bmnfd approved
certificatesigningrequest.certificates.k8s.io/csr-hwl89 approved
```

### Next steps

**Recommended - Security**

- [Secure Calico component communications]({{site.baseurl}}/security/comms/crypto-auth)
- [Secure hosts by installing Calico on hosts]({{site.baseurl}}/getting-started/bare-metal/about)
- [Secure pods with Calico network policy]({{site.baseurl}}/security/calico-network-policy)
- If you are using {{site.prodname}} with Istio service mesh, get started here: [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy)
