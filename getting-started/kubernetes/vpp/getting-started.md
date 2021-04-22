---
title: Get started with VPP networking
description: Install Calico with the VPP dataplane on a Kubernetes cluster.
canonical_url: '/getting-started/kubernetes/vpp/getting-started'
---


### Big picture

Install {{site.prodname}} and enable the tech preview of the VPP dataplane.

> **Warning!** The VPP dataplane is a tech preview and should not be used in production clusters. It has had limited testing and it will contain bugs (please report these on the [Calico Users slack](https://calicousers.slack.com/archives/C017220EXU1) or [Github](https://github.com/projectcalico/vpp-dataplane/issues)).  In addition, it does not support all the features of {{site.prodname}} and it is currently missing some security features such as Host Endpoint policies.
{: .alert .alert-danger }

### Value

The VPP dataplane mode has several advantages over standard Linux networking pipeline mode:

* Scales to higher throughput, especially with WireGuard encryption enabled
* Further improves encryption performance with IPsec
* Native support for Kubernetes services without needing kube-proxy, which:
  * Reduces first-packet latency for packets to services
  * Preserves external client source IP addresses all the way to the pod

The VPP dataplane is entirely compatible with the other {{site.prodname}} dataplanes, meaning you can have a cluster with VPP-enabled nodes along with regular nodes. This makes it easy to migrate a cluster from Linux or eBPF networking to VPP networking.

In the future, the VPP dataplane will offer additional features for network-intensive applications, such as providing `memif` userspace packet interfaces to the pods (instead of regular Linux network devices).

Trying out the tech preview will give you a taste of these benefits and an opportunity to give feedback to the VPP dataplane team.


### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **VPP dataplane**

### Concepts

#### VPP

The Vector Packet Processor (VPP) is a high-performance, open-source userspace network dataplane written in C, developed under the [fd.io](https://fd.io) umbrella. It supports many standard networking features (L2, L3 routing, NAT, encapsulations), and is easily extensible using plugins. The VPP dataplane uses plugins to efficiently implement Kubernetes services load balancing and {{site.prodname}} policies.

### How to

This guide details two ways to install {{site.prodname}} with the VPP dataplane:
- On a managed EKS cluster. This is the option that requires the least configuration
- On any Kubernetes cluster

In both cases, here are the details of what you will get:

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:Kubernetes' %}



{% tabs %}
<label:Install on EKS,active:true>
<%

### Install Calico with the VPP dataplane on an EKS cluster

#### Requirements

For these instructions, we will use `eksctl` to provision the cluster. However, you can use any of the methods in {% include open-new-window.html text='Getting Started with Amazon EKS' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html' %}

Before you get started, make sure you have downloaded and configured the {% include open-new-window.html text='necessary prerequisites' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html#eksctl-prereqs' %}

#### Provision and configure the cluster

1. First, create an Amazon EKS cluster without any nodes.

   ```bash
   eksctl create cluster --name my-calico-cluster --without-nodegroup
   ```

1. Since this cluster will use {{site.prodname}} for networking, you must delete the `aws-node` daemon set to disable AWS VPC networking for pods.

   ```bash
   kubectl delete daemonset -n kube-system aws-node
   ```

1. Now that you have a cluster configured, you can install {{site.prodname}}.

   Standard install:
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/generated/calico-vpp-eks.yaml
   ```
   Install using the optional DPDK driver for better networking performance:
   ```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/generated/calico-vpp-eks-dpdk.yaml
```

1. Finally, add nodes to the cluster.

   ```bash
   eksctl create nodegroup --cluster my-calico-cluster --node-type t3.medium --node-ami auto --max-pods-per-node 100
   ```

   > **Tip**: The --max-pods-per-node option above, ensures that EKS does not limit the {% include open-new-window.html text='number of pods based on node-type' url='https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt' %}. For the full set of node group options, see `eksctl create nodegroup --help`.
   {: .alert .alert-success}

%>
<label:Install on any cluster>
<%

### Install Calico with the VPP dataplane on any Kubernetes cluster

#### Requirements

The VPP dataplane has the following requirements:

**Required**
- A blank Kubernetes cluster, where no CNI was ever configured.
- These [base requirements]({{site.baseurl}}/getting-started/kubernetes/requirements), except those related to the management of `cali*`, `tunl*` and `vxlan.calico` interfaces.

**Optional**
For some hardware, the following hugepages configuration may enable VPP to use more efficient drivers:

- At least 128 x 2MB-hugepages are available (`cat /proc/meminfo | grep HugePages_Free`)
- The `vfio-pci` (`vfio_pci` on centos) or `uio_pci_generic` kernel module is loaded. For example:

   ````bash
   echo "vfio-pci" > /etc/modules-load.d/95-vpp.conf
   modprobe vfio-pci
   echo "vm.nr_hugepages = 128" >> /etc/sysctl.conf
   sysctl -p
   # restart kubelet to take the changes into account, you may need to use a different command depending on how kubelet was installed
   systemctl restart kubelet
   ````

#### Configure nodes for VPP

Start by getting the appropriate yaml manifest for the {{ site.prodname }} VPP dataplane:
```bash
# If you have configured hugepages on your machines
curl -o calico-vpp.yaml https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/generated/calico-vpp.yaml
```
```bash
# If not, or if you're unsure
curl -o calico-vpp.yaml https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/generated/calico-vpp-nohuge.yaml
```

Then configure these parameters in the `calico-config` ConfigMap in the yaml manifest.

**Required**

* `vpp_dataplane_interface` is the primary interface that VPP will use. It must be the name of a Linux interface, configured with an address. The address configured on this interface must be the node address in Kubernetes (`kubectl get nodes -o wide`).
* `service_prefix` is the Kubernetes service CIDR. You can retrieve it by running:
````bash
kubectl cluster-info dump | grep -m 1 service-cluster-ip-range
````
If this command doesn't return anything, you can leave the default value of `10.96.0.0/12`.

**Optional**

* `default_ipv4_pool_cidr` allows you to customize the default {{ site.prodname }} IPv4 pool. For details, see [reference]({{ site.baseurl }}/reference/node/configuration)
* `vpp_uplink_driver` configures how VPP grabs the physical interface, available values are:
  * `""` : will automatically select and try drivers based on available resources, starting with the fastest
  * `avf` : use the native AVF driver
  * `virtio` : use the native virtio driver (requires hugepages)
  * `af_xdp` : use an AF_XDP socket to drive the interface (requires kernel 5.4 or newer)
  * `af_packet` : use an AF_PACKET socket to drive the interface (slow but works everywhere)
  * `none` : do not configure connectivity automatically. This can be used when [configuring the interface manually]({{ site.baseurl }}/reference/vpp/uplink-configuration)

**Example**

````yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-config
  namespace: kube-system
data:
  service_prefix: 10.96.0.0/12
  vpp_dataplane_interface: eth1
  default_ipv4_pool_cidr: 172.16.0.0/16
  vpp_uplink_driver: ""
  ...
````

#### Apply the configuration

To apply the configuration, run:
````bash
kubectl apply -f calico-vpp.yaml
````

This will create all the resources necessary to connect your pods through VPP and configure Calico on the nodes.

%>
{% endtabs %}




### Next steps

After installing {{ site.prodname }} with the VPP dataplane, you can benefit from the features of the VPP dataplane, such as fast [IPsec]({{ site.baseurl }}/getting-started/kubernetes/vpp/ipsec) or [Wireguard]({{ site.baseurl }}/security/encrypt-cluster-pod-traffic) encryption.

**Tools**

- [Install and configure calicoctl]({{site.baseurl}}/getting-started/clis/calicoctl/install) to configure and monitor your cluster.

**Security**

- [Secure pods with {{ site.prodname }} network policy]({{site.baseurl}}/security/calico-network-policy)
