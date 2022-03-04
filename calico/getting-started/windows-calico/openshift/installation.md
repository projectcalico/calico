---
title: Install an OpenShift 4 cluster on Windows nodes
description: Install Calico on an OpenShift 4 cluster on Windows nodes
canonical_url: '/getting-started/windows-calico/openshift/installation'
---

### Big picture

Install an OpenShift 4 cluster on AWS with {{site.prodname}} on Windows nodes.

### Value

Run Windows workloads on OpenShift 4 with {{site.prodname}}.

### How to

#### Before you begin

- Ensure that your environment meets the {{site.prodname}} [system requirements]({{site.baseurl}}/getting-started/openshift/requirements).

- Ensure that you have {% include open-new-window.html text='configured an AWS account' url='https://docs.openshift.com/container-platform/4.4/installing/installing_aws/installing-aws-account.html' %} appropriate for OpenShift 4,
  and have {% include open-new-window.html text='set up your AWS credentials' url='https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html' %}.
  Note that the OpenShift installer supports a subset of {% include open-new-window.html text='AWS regions' url='https://docs.openshift.com/container-platform/4.4/installing/installing_aws/installing-aws-account.html#installation-aws-regions_installing-aws-account' %}.

- Ensure that you have a {% include open-new-window.html text='RedHat account' url='https://cloud.redhat.com/' %}. A RedHat account is required to obtain the pull secret necessary to provision an OpenShift cluster.

- Ensure that you have installed the OpenShift installer **v4.4 or later** and OpenShift command line interface from {% include open-new-window.html text='cloud.redhat.com' url='https://cloud.redhat.com/openshift/install/aws/installer-provisioned' %}.

- Ensure that you have {% include open-new-window.html text='generated a local SSH private key' url='https://docs.openshift.com/container-platform/4.4/installing/installing_aws/installing-aws-default.html#ssh-agent-using_installing-aws-default' %} and have added it to your ssh-agent

**Limitations**

Due to an {% include open-new-window.html text='upstream issue' url='https://bugzilla.redhat.com/show_bug.cgi?id=1768858' %}, Windows pods can only be run in specific namespaces if you disable SCC.
To do this, label the namespace with `openshift.io/run-level: "1"`.

#### Create a configuration file for the OpenShift installer

First, create a staging directory for the installation. This directory will contain the configuration file, along with cluster state files, that OpenShift installer will create:

```bash
mkdir openshift-tigera-install && cd openshift-tigera-install
```

Now run OpenShift installer to create a default configuration file:

```bash
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

```bash
oc get tigerastatus
```

> **Note**: To get more information, add `-o yaml` to the above command.

Next, [install calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install) and ensure strict affinity is true:

```bash
calicoctl ipam configure --strictaffinity=true
```

#### Add Windows nodes to the cluster

Download the latest {% include open-new-window.html text='Windows Node Installer (WNI)' url='https://github.com/openshift/windows-machine-config-bootstrapper/releases' %} binary `wni` that matches your OpenShift minor version.

> **Note**: For OpenShift 4.6, use the latest wni for OpenShift 4.5. A wni binary for OpenShift 4.6 is not published yet.
{: .alert .alert-info}

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

#### Get the administrator password

The `wni` binary writes the instance details to the file `windows-node-installer.json`. An example of the file:

```
{"InstanceIDs":["i-02e13d4cc76c13c83"],"SecurityGroupIDs":["sg-0a777565d64e1d2ef"]}
```

Use the instance ID from the file and the path of the private key used to create the instance to get the Administrator user's password:

```bash
aws ec2 get-password-data --instance-id <instance id> --priv-launch-key <aws private key path>
```

#### Install {{site.prodnameWindows}}

1. Remote into the Windows node, open a Powershell window, and prepare the directory for Kubernetes files.

   ```powershell
   mkdir c:\k
   ```

1. Copy the Kubernetes kubeconfig file (default location: openshift-tigera-install/auth/kubeconfig), to the file **c:\k\config**.

1. Download the powershell script, **install-calico-windows.ps1**.

   ```powershell
   Invoke-WebRequest {{ "/scripts/install-calico-windows.ps1" | absolute_url }} -OutFile c:\install-calico-windows.ps1
   ```

1. Run the installation script, replacing the Kubernetes version with the version corresponding to your version of OpenShift.

   ```powershell
   c:\install-calico-windows.ps1 -KubeVersion <kube version> -ServiceCidr 172.30.0.0/16 -DNSServerIPs 172.30.0.10
   ```

   > **Note**: Get the Kubernetes version with `oc version` and use only the major, minor, and patch version numbers. For example from a cluster that returns:
   ```
   $ oc version
   Client Version: 4.5.3
   Server Version: 4.5.14
   Kubernetes Version: v1.18.3+5302882
   ```
   You will use `1.18.3`:
   {: .alert .alert-info}

1. Install and start kube-proxy service. Execute following powershell script/commands.

   ```powershell
   C:\CalicoWindows\kubernetes\install-kube-services.ps1 -service kube-proxy
   Start-Service -Name kube-proxy
   ```

1. Verify kube-proxy service is running.

   ```powershell
   Get-Service -Name kube-proxy
   ```

#### Configure kubelet

From the Windows node, download the Windows Machine Config Bootstrapper `wmcb.exe` that matches your OpenShift minor version from {% include open-new-window.html text='Windows Machine Config Bootstrapper releases' url='https://github.com/openshift/windows-machine-config-bootstrapper/releases' %}. For example, for OpenShift 4.5.x:

```powershell
curl https://github.com/openshift/windows-machine-config-bootstrapper/releases/download/v4.5.2-alpha/wmcb.exe -o c:\wmcb.exe
```

> **Note**: For OpenShift 4.6, use the latest wmcb.exe for OpenShift 4.5. A wmcb.ex binary for OpenShift 4.6 is not published yet.
{: .alert .alert-info}

Next, we will download the the `worker.ign` file from the API server:

```powershell
$apiServer = c:\k\kubectl --kubeconfig c:\k\config get po -n  openshift-kube-apiserver -l apiserver=true --no-headers -o custom-columns=":metadata.name" | select -first 1
c:\k\kubectl --kubeconfig c:\k\config -n openshift-kube-apiserver exec $apiserver -- curl -ks https://localhost:22623/config/worker > c:\worker.ign
((Get-Content c:\worker.ign) -join "`n") + "`n" | Set-Content -NoNewline c:\worker.ign
```

Next, we run wmcb to configure the kubelet:

```powershell
c:\wmcb.exe initialize-kubelet --ignition-file worker.ign --kubelet-path c:\k\kubelet.exe
```

> **Note**: The kubelet configuration installed by Windows Machine Config
> Bootstrapper includes `--register-with-taints="os=Windows:NoSchedule"` which
> will require Windows pods to tolerate that taint.
{: .alert .alert-info}

Next, we make a copy of the kubeconfig because `wmcb.exe` expects the kubeconfig to be the file `c:\k\kubeconfig`.
Then we configure kubelet to use Calico CNI:

```powershell
cp c:\k\config c:\k\kubeconfig
c:\wmcb.exe configure-cni --cni-dir c:\k\cni --cni-config c:\k\cni\config\10-calico.conf
```

Finally, clean up the additional files created on the Windows node:

```powershell
rm c:\k\kubeconfig,c:\wmcb.exe,c:\worker.ign
```

Exit the remote session to the Windows node and return to a shell to a Linux
node.

We need to approve the CSR's generated by the kubelet's bootstrapping process. First, view the pending CSR's:

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

Finally, wait a minute or so and get all nodes:

```
$ oc get node -owide
```

If the Windows node registered itself successfully, it should appear in the list with a Ready status, ready to run Windows pods!

### Next steps

**Recommended - Security**

- [Secure Calico component communications]({{site.baseurl}}/security/comms/crypto-auth)
- [Secure pods with Calico network policy]({{site.baseurl}}/security/calico-network-policy)
- If you are using {{site.prodname}} with Istio service mesh, get started here: [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy)
