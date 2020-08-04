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
   > not specific to {{site.prodname}}.) As a workaround, you can setup a multi CNI cluster using Multus or modify trusted pods that require control plane nodes to connect to them, such as those implementing
   > admission controller webhooks, can include `hostNetwork:true` in their pod spec. See the Kuberentes API
   > {% include open-new-window.html text='pod spec' url='https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#podspec-v1-core' %}
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

   ```bash
   kubectl apply -f {{ "/manifests/calico-vxlan.yaml" | absolute_url }}
   ```
{% tabs %}
<label:EKS,active:true>
<%
   Finally, add nodes to the cluster.

   ```bash
   eksctl create nodegroup --cluster my-calico-cluster --node-type t3.medium --node-ami auto --max-pods-per-node 100
   ```

   > **Tip**: Without the `--max-pods-per-node` option above, EKS will limit the {% include open-new-window.html text='number of pods based on node-type' url='https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt' %}. See `eksctl create nodegroup --help` for the full set of node group options.
   {: .alert .alert-success}
%>
<label:Multus>
<%

> Multus CNI is an open source Kubernetes CNI plugin, it allows attaching multiple interfaces to pods. By acting as a `meta-plugin` Multus can 
> override Kubernetes default network CNI configuration and assign interfaces to different CNI plugin.
{: .alert .alert-info}

**Installing Multus**

You can install Multus using manifest.

```bash
kubectl apply -f https://raw.githubusercontent.com/openshift/multus-cni/master/images/multus-daemonset.yml
```

**Installing aws-k8s-cni**

> **Note**: Using default configuration with AWS CNI causes IPAMD to consume all available IP addresses in EC2 instances participating in the node group at the beginning. You can alter this behavior by using environment variables such as `MINIMUM_IP_TARGET` and `WARM_IP_TARGET`. 
>
> **Note**: It is important to use AWS CNI plugin version **1.6.0** or higher because older releases do not support `MINIMUM_IP_TARGET` environment variable.
> 
> More details can be found {% include open-new-window.html text="at this page." url='https://github.com/aws/amazon-vpc-cni-k8s' %}
{: .alert .alert-info }

Install `aws-k8s-cni` plugin

```bash
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/v1.6/aws-k8s-cni.yaml
```

**Add aws-k8s-cni configuration to Multus**

Multus uses custom resources to configure different CNI plugins.

You can add `aws-k8s-cni` to Multus by Creating a `NetworkAttachmentDefinition` with plugin configuration parameters.

```bash
kubectl apply -f - <<EOF
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: aws-cni
  namespace: kube-system
spec:
  config: '{
  "cniVersion": "0.3.1",
  "name": "aws-cni",
  "plugins": [
    {
      "name": "aws-cni",
      "type": "aws-cni",
      "vethPrefix": "eni",
      "mtu": "9001",
      "pluginLogFile": "/var/log/aws-routed-eni/plugin.log",
      "pluginLogLevel": "Debug"
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true},
      "snat": true
    }
  ]
}'
EOF
```

Congratulations! your EKS cluster is now equipped with three CNI plugins.

**Demo** 

Create a namespace to isolate demo resources.

```bash
kubectl create namespace calico-multus-demo
```

By using `v1.multus-cni.io/default-network` annotation and providing `aws-cni` as value you
can 

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  namespace: calico-multus-demo
  name: awspod
  labels:
    app: awspod
  annotations:
    v1.multus-cni.io/default-network: aws-cni
spec:
  containers:
  - name: awspod
    image: nginx:1.14.2
    ports:
    - containerPort: 80
EOF
```

Create a different Pod without applying Multus crd annotations. This causes the Pod to acquire an IP address from {{site.prodname}}.

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  namespace: calico-multus-demo
  name: calicopod
  labels:
    app: calicopod
spec:
  containers:
  - name: calicopod
    image: nginx:1.14.2
    ports:
    - containerPort: 80
EOF
```

Create a service for each pod.

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: calicopod-service
  namespace: calico-multus-demo
spec:
  selector:
    app: calicopod
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: awspod-service
  namespace: calico-multus-demo
spec:
  selector:
    app: awspod
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
EOF
```

**Testing control plane connectivity**

> kubectl `proxy` provides access to Kubernetes API using apiserver.
>
> If you like to learn more about this feature {% include open-new-window.html text="click here." url='https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-services/' %}
{: .alert .alert-info}

Run kubectl in proxy mode

```bash
kubectl proxy
```

You should see an output similar to

```
Starting to serve on 127.0.0.1:8001
```

At this point you should be able to browse `awspod` home page {% include open-new-window.html text='by clicking here.' url='http://localhost:8001/api/v1/namespaces/calico-multus-demo/services/awspod-service/proxy/' %}

{% include open-new-window.html text='Pod not reachable by conrol plane.' url='http://localhost:8001/api/v1/namespaces/calico-multus-demo/services/calicopod-service/proxy/' %}


**Cleanup**

Remove demo resources

```bash
kubectl delete namespace calico-multus-demo
```

%>
{% endtabs %}
### Next steps

**Required**
- [Install calicoctl command line tool]({{ site.baseurl }}/getting-started/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes pod networking' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-pod-networking-on-aws/' %}
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with {{site.prodname}} network policy]({{ site.baseurl }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.baseurl }}/security/kubernetes-default-deny)
