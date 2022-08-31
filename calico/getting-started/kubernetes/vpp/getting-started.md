---
title: Get started with VPP networking
description: Install Calico with the VPP dataplane on a Kubernetes cluster.
canonical_url: '/getting-started/kubernetes/vpp/getting-started'
---


### Big picture

Install {{site.prodname}} and enable the beta release of the VPP dataplane.

> **Warning!** The VPP dataplane is in beta and should not be used in production clusters. It has had lots of testing and is pretty stable. However, chances are that some bugs are still lurking around (please report these on the [Calico Users slack](https://calicousers.slack.com/archives/C017220EXU1) or [Github](https://github.com/projectcalico/vpp-dataplane/issues)).  In addition, it still does not support all the features of {{site.prodname}}.
{: .alert .alert-danger }

### Value

The VPP dataplane mode has several advantages over standard Linux networking pipeline mode:

* Scales to higher throughput, especially with WireGuard encryption enabled
* Further improves encryption performance with IPsec
* Native support for Kubernetes services without needing kube-proxy, which:
  * Reduces first-packet latency for packets to services
  * Preserves external client source IP addresses all the way to the pod

The VPP dataplane is entirely compatible with the other {{site.prodname}} dataplanes, meaning you can have a cluster with VPP-enabled nodes along with regular nodes. This makes it possible to migrate a cluster from Linux or eBPF networking to VPP networking.

In addition, the VPP dataplane offers some specific features for network-intensive applications, such as providing `memif` userspace packet interfaces to the pods (instead of regular Linux network devices), or exposing the VPP Host Stack to run optimized L4+ applications in the pods.

Trying out the beta will give you a taste of these benefits and an opportunity to give feedback to the VPP dataplane team.


### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **VPP dataplane**

### Concepts

#### VPP

The Vector Packet Processor (VPP) is a high-performance, open-source userspace network dataplane written in C, developed under the [fd.io](https://fd.io) umbrella. It supports many standard networking features (L2 switching, L3 routing, NAT, encapsulations), and is easily extensible using plugins. The VPP dataplane uses plugins to efficiently implement Kubernetes services load balancing and {{site.prodname}} policies.

#### Operator based installation

This guide uses the Tigera operator to install {{site.prodname}}. The operator provides lifecycle management for {{site.prodname}}
exposed via the Kubernetes API defined as a custom resource definition. While it is also technically possible to install {{site.prodname}}
and configure it for VPP using manifests directly, only operator based installations are supported at this stage.


### How to

This guide details two ways to install {{site.prodname}} with the VPP dataplane:
- On a managed EKS cluster. This is the option that requires the least configuration
- On a managed EKS cluster with the DPDK interface driver. This options is more complex to setup but provides better performance
- On any Kubernetes cluster

In all cases, here are the details of what you will get:

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:Kubernetes' %}



{% tabs %}
<label:Install on EKS,active:true>
<%

### Install Calico with the VPP dataplane on an EKS cluster

#### Requirements

For these instructions, we will use `eksctl` to provision the cluster. However, you can use any of the methods in {% include open-new-window.html text='Getting Started with Amazon EKS' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html' %}

Before you get started, make sure you have downloaded and configured the {% include open-new-window.html text='necessary prerequisites' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html#eksctl-prereqs' %}

#### Provision the cluster

1. First, create an Amazon EKS cluster without any nodes.

   ```bash
   eksctl create cluster --name my-calico-cluster --without-nodegroup
   ```

1. Since this cluster will use {{site.prodname}} for networking, you must delete the `aws-node` DaemonSet to disable the default AWS VPC networking for the pods.

   ```bash
   kubectl delete daemonset -n kube-system aws-node
   ```


#### Install and configure Calico with the VPP dataplane

1. Now that you have an empty cluster configured, you can install the Tigera operator. 

   ```bash
   kubectl apply -f {{site.data.versions.manifests_url}}/manifests/tigera-operator.yaml
   ```

1. Then, you need to configure the {{site.prodname}} installation for the VPP dataplane. The yaml in the link below contains a minimal viable configuration for EKS. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

   > **Note**: Before applying this manifest, read its contents and make sure its settings are correct for your environment. For example,
   > you may need to specify the default IP pool CIDR to match your desired pod network CIDR.
   {: .alert .alert-info}

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/calico/installation-eks.yaml
   ```

1. Now is time to install the VPP dataplane components.

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/generated/calico-vpp-eks.yaml
   ```

1. Finally, add nodes to the cluster.

   ```bash
   eksctl create nodegroup --cluster my-calico-cluster --node-type t3.medium --node-ami auto --max-pods-per-node 50
   ```

   > **Tip**: The --max-pods-per-node option above, ensures that EKS does not limit the {% include open-new-window.html text='number of pods based on node-type' url='https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt' %}. For the full set of node group options, see `eksctl create nodegroup --help`.
   {: .alert .alert-success}


%>

<label:Install on EKS with DPDK>
<%

### Install Calico with the VPP dataplane on an EKS cluster with the DPDK driver

#### Requirements

DPDK provides better performance compared to the standard install but it requires some additional customisations (hugepages, for instance) in the EKS worker instances. We have a bash script, `init_eks.sh`, which takes care of applying the required customizations and we make use of the `preBootstrapCommands` property of `eksctl` {% include open-new-window.html text='configuration file' url='https://eksctl.io/usage/schema' %} to execute the script during the worker node creation. These instructions require the latest version of `eksctl`.


#### Provision the cluster

1. First, create an Amazon EKS cluster without any nodes.

   ```bash
   eksctl create cluster --name my-calico-cluster --without-nodegroup
   ```

2. Since this cluster will use {{site.prodname}} for networking, you must delete the `aws-node` DaemonSet to disable the default AWS VPC networking for the pods.

   ```bash
   kubectl delete daemonset -n kube-system aws-node
   ```


#### Install and configure Calico with the VPP dataplane

1. Now that you have an empty cluster configured, you can install the Tigera operator. 

   ```bash
   kubectl apply -f {{site.data.versions.manifests_url}}/manifests/tigera-operator.yaml
   ```

2. Then, you need to configure the {{site.prodname}} installation for the VPP dataplane. The yaml in the link below contains a minimal viable configuration for EKS. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

   > **Note**: Before applying this manifest, read its contents and make sure its settings are correct for your environment. For example,
   > you may need to specify the default IP pool CIDR to match your desired pod network CIDR.
   {: .alert .alert-info}

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/calico/installation-eks.yaml
   ```

3. Now is time to install the VPP dataplane components.

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/generated/calico-vpp-eks-dpdk.yaml
   ```

4. Finally, time to add nodes to the cluster. Since we need to customize the nodes for DPDK, we will use an `eksctl` config file with the `preBootstrapCommands` property to create the worker nodes. The following command will create a managed nodegroup with 2 t3.large worker nodes in the cluster:


   ```
   cat <<EOF | eksctl create nodegroup -f -
   apiVersion: eksctl.io/v1alpha5
   kind: ClusterConfig
   metadata:
     name: my-calico-cluster
     region: us-east-2
   managedNodeGroups:
   - name: my-calico-cluster-ng
     desiredCapacity: 2
     instanceType: t3.large
     labels: {role: worker}
     preBootstrapCommands:
       - sudo curl -o /tmp/init_eks.sh "https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/scripts/init_eks.sh"
       - sudo chmod +x /tmp/init_eks.sh
       - sudo /tmp/init_eks.sh
   EOF
   ```
   
   Please edit the cluster name, region and other fields as appropriate for your cluster. In case you want to enable ssh access to the EKS worker instances, add the following to the above config file:
   
   ```
     ssh:
       publicKeyPath: <path to public key>
   ```
   
   For details on ssh access refer to {% include open-new-window.html text='Amazon EC2 key pairs and Linux instances' url='https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html' %}.
%>

<label:Install on any cluster>
<%

### Install Calico with the VPP dataplane on any Kubernetes cluster

#### Requirements

The VPP dataplane has the following requirements:

**Required**
- A blank Kubernetes cluster, where no CNI was ever configured.
- These [base requirements]({{site.baseurl}}/getting-started/kubernetes/requirements), except those related to the management of `cali*`, `tunl*` and `vxlan.calico` interfaces.

   > **Note**: If you are using `kubeadm` to create the cluster please make sure to specify the pod network CIDR using the `--pod-network-cidr` command-line argument, i.e., `sudo kubeadm init --pod-network-cidr=192.168.0.0/16`. If 192.168.0.0/16 is already in use within your network you must select a different pod network CIDR.
   {: .alert .alert-info}

**Optional**
For some hardware, the following hugepages configuration may enable VPP to use more efficient drivers:

- At least 512 x 2MB-hugepages are available (`grep HugePages_Free /proc/meminfo`)
- The `vfio-pci` (`vfio_pci` on centos) or `uio_pci_generic` kernel module is loaded. For example:

   ````bash
   echo "vfio-pci" > /etc/modules-load.d/95-vpp.conf
   modprobe vfio-pci
   echo "vm.nr_hugepages = 512" >> /etc/sysctl.conf
   sysctl -p
   # restart kubelet to take the changes into account
   # you may need to use a different command depending on how kubelet was installed
   systemctl restart kubelet
   ````

#### Install Calico and configure it for VPP

1. Start by installing the Tigera operator on your cluster. 

   ```bash
   kubectl apply -f {{site.data.versions.manifests_url}}/manifests/tigera-operator.yaml
   ```

1. Then, you need to configure the {{site.prodname}} installation for the VPP dataplane. The yaml in the link below contains a minimal viable configuration for VPP. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

   > **Note**: Before applying this manifest, read its contents and make sure its settings are correct for your environment. For example,
   > you may need to specify the default IP pool CIDR to match your desired pod network CIDR.
   {: .alert .alert-info}

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/calico/installation-default.yaml
   ```

#### Install the VPP dataplane components

Start by getting the appropriate yaml manifest for the VPP dataplane resources:
```bash
# If you have configured hugepages on your machines
curl -o calico-vpp.yaml https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/generated/calico-vpp.yaml
```
```bash
# If not, or if you're unsure
curl -o calico-vpp.yaml https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/generated/calico-vpp-nohuge.yaml
```

Then locate the `calico-vpp-config` ConfigMap in this yaml manifest and configure it as follows.

**Required**

* `vpp_dataplane_interface` is the primary interface that VPP will use. It must be the name of a Linux interface, up and configured with an address. The address configured on this interface **must** be the node address in Kubernetes (`kubectl get nodes -o wide`).
* `service_prefix` is the Kubernetes service CIDR. You can retrieve it by running:
````bash
kubectl cluster-info dump | grep -m 1 service-cluster-ip-range
````
If this command doesn't return anything, you can leave the default value of `10.96.0.0/12`.

**Optional**

* `vpp_uplink_driver` configures how VPP drives the physical interface. The supported values will depend on the interface type. Available values are:
  * `""` : will automatically select and try drivers based on interface type and available resources, starting with the fastest
  * `af_xdp` : use an AF_XDP socket to drive the interface (requires kernel 5.4 or newer)
  * `af_packet` : use an AF_PACKET socket to drive the interface (not optimized but works everywhere)
  * `avf` : use the VPP native driver for Intel 700-Series and 800-Series interfaces (requires hugepages)
  * `vmxnet3` : use the VPP native driver for VMware virtual interfaces (requires hugepages)
  * `virtio` : use the VPP native driver for Virtio virtual interfaces  (requires hugepages)
  * `rdma` : use the VPP native driver for Mellanox CX-4 and CX-5 interfaces (requires hugepages)
  * `dpdk` : use the DPDK interface drivers with VPP (requires hugepages, works with most interfaces)
  * `none` : do not configure connectivity automatically. This can be used when [configuring the interface manually]({{ site.baseurl }}/reference/vpp/uplink-configuration)

**Example**

````yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-config
  namespace: calico-vpp-dataplane
data:
  service_prefix: 10.96.0.0/12
  vpp_dataplane_interface: eth1
  vpp_uplink_driver: ""
  ...
````

#### Apply the configuration

To apply the configuration, run:
````bash
kubectl apply -f calico-vpp.yaml
````

This will install all the resources required by the VPP dataplane in your cluster.

%>
{% endtabs %}




### Next steps

After installing {{ site.prodname }} with the VPP dataplane, you can benefit from the features of the VPP dataplane, such as fast [IPsec]({{ site.baseurl }}/getting-started/kubernetes/vpp/ipsec) or [Wireguard]({{ site.baseurl }}/security/encrypt-cluster-pod-traffic) encryption.

**Tools**

- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install) to configure and monitor your cluster.

**Security**

- [Secure pods with {{ site.prodname }} network policy]({{site.baseurl}}/security/calico-network-policy)
