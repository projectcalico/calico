---
title: Amazon Elastic Kubernetes Service (EKS)
description: Enable Calico network policy in EKS.
---

### Big picture

Enable {{site.prodname}} in EKS managed Kubernetes service.

### Value

EKS has built-in support for {{site.prodname}}, providing a robust implementation of the full Kubernetes Network Policy API. EKS users wanting to go beyond Kubernetes network policy capabilities can make full use of the Calico Network Policy API.

You can also use {{site.prodname}} for networking on EKS in place of the default AWS VPC networking without the need to use IP addresses from the underlying VPC. This allows you to take advantage of the full set of {{site.prodname}} networking features, including {{site.prodname}}'s flexible IP address management capabilities.

### How to

#### Install EKS with Amazon VPC networking

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:AWS,CNI:AWS,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

To enable {{site.prodname}} network policy enforcement on an EKS cluster using the AWS VPC CNI plugin, follow these step-by-step instructions: {% include open-new-window.html text='Installing Calico on Amazon EKS' url='https://docs.aws.amazon.com/eks/latest/userguide/calico.html' %}

#### Install EKS with {{site.prodname}} networking

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

   > **Note**: {{site.prodname}} networking cannot currently be installed on the EKS control plane nodes. As a result the control plane nodes
   > will not be able to initiate network connections to {{site.prodname}} pods. (This is a general limitation of EKS's custom networking support,
   > not specific to {{site.prodname}}.) As a workaround, trusted pods that require control plane nodes to connect to them, such as those implementing
   > admission controller webhooks, can include `hostNetwork:true` in their pod spec. See the Kubernetes API
   > {% include open-new-window.html text='pod spec' url='https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#podspec-v1-core' %}
   > definition for more information on this setting.
   {: .alert .alert-info }

For these instructions, we will use `eksctl` to provision the cluster. However, you can use any of the methods in {% include open-new-window.html text='Getting Started with Amazon EKS' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html' %}

Before you get started, make sure you have downloaded and configured the {% include open-new-window.html text='necessary prerequisites' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html#eksctl-prereqs' %}

1. First, create an Amazon EKS cluster without any nodes.

   ```bash
   eksctl create cluster --name my-calico-cluster --without-nodegroup
   ```

1. Since this cluster will use {{site.prodname}} for networking, you must delete the `aws-node` daemon set to disable AWS VPC networking for pods.

   ```bash
   kubectl delete daemonset -n kube-system aws-node
   ```

1. Now that you have a cluster configured, you can install {{site.prodname}}.

{% tabs %}
  <label:Operator,active:true>
<%

1. Install the operator.

   ```bash
   kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
   ```

1. Configure the {{site.prodname}} installation.

   ```bash
   kubectl create -f - <<EOF
   kind: Installation
   apiVersion: operator.tigera.io/v1
   metadata:
     name: default
   spec:
     kubernetesProvider: EKS
     cni:
       type: Calico
     calicoNetwork:
       bgp: Disabled
   EOF
   ```

%>
  <label:Manifest>
<%

1. Install the {{site.prodname}} manifest.

   ```bash
   kubectl apply -f {{ "/manifests/calico-vxlan.yaml" | absolute_url }}
   ```

1. Configure {{site.prodname}} to disable AWS src/dst checks.

   ```bash
   kubectl -n kube-system set env daemonset/calico-node FELIX_AWSSRCDSTCHECK=Disable
   ```
%>
{% endtabs %}

1. Finally, add nodes to the cluster.

   ```bash
   eksctl create nodegroup --cluster my-calico-cluster --node-type t3.medium --max-pods-per-node 100
   ```

   > **Tip**: Without the `--max-pods-per-node` option above, EKS will limit the {% include open-new-window.html text='number of pods based on node-type' url='https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt' %}. See `eksctl create nodegroup --help` for the full set of node group options.
   {: .alert .alert-success}

### Next steps

**Required**
- [Install calicoctl command line tool]({{ site.baseurl }}/maintenance/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes pod networking on AWS' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-pod-networking-on-aws/' %}
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with {{site.prodname}} network policy]({{ site.baseurl }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.baseurl }}/security/kubernetes-default-deny)
