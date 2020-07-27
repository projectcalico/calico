---
title: Amazon Elastic Kubernetes Service (EKS) Using Calico and Multus
description: Using Multus in an EKS environment
---

### Big picture

Enabling multiple CNI plugins in an EKS cluster using Multus-CNI.

### Value

Multus CNI is an open source Kubernetes CNI plugin, it allows attaching multiple interfaces to pods. By acting as a `meta-plugin` Multus can 
override Kubernetes default network CNI configuration and assign interfaces to different CNI plugin.

Multus integration with {{site.prodname}} offers great flexibility in EKS clusters, it can be a solution for EKS control plane limitations 
when using custom networking in a managed nodes cluster environment.

> **Note**: {{site.prodname}} networking cannot currently be installed on the EKS control plane nodes. As a result the control plane nodes
> will not be able to initiate network connections to {{site.prodname}} pods. (This is a general limitation of EKS's custom networking support,
> not specific to {{site.prodname}}.) 
{: .alert .alert-info }

### How to

This tutorial will guide you to install Multus, {{site.prodname}} and aws-k8s-cni in a Kubernetes cluster, we will use `eksctl` to provision the cluster. However, you can use any of the methods in {% include open-new-window.html text='Getting Started with Amazon EKS' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html' %}

Before you get started, make sure you have downloaded and configured the {% include open-new-window.html text='necessary prerequisites' url='https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html#eksctl-prereqs' %}

#### Create the cluster

Create an Amazon EKS cluster without any nodes.

```bash
eksctl create cluster --name calico-multus --without-nodegroup
```

> **Note**: Multus scans `/etc/cni/net.d/` folder in alphabetic order for files with `conf` or `conflist` 
extension. To promote {{site.prodname}} as your primary CNI you have to delete `aws-node` from your cluster.
{: .alert .alert-info }

Delete `amazon-vpc-cni-k8s` daemonset

```bash
kubectl delete daemonset -n kube-system aws-node
```

You should see an output similar to

```
daemonset.apps "aws-node" deleted
```

#### Install {{ site.prodname }}

Now that you have a cluster configured, you can install {{site.prodname}}.

```bash
kubectl apply -f {{ "/manifests/calico-vxlan.yaml" | absolute_url }}
```

Add nodes to the cluster.

```bash
eksctl create nodegroup --cluster calico-multus --node-type t3.medium --node-ami auto --max-pods-per-node 100
```

> **Tip**: Without the --max-pods-per-node option above, EKS will limit the number of pods based on node-type. 
> See eksctl create nodegroup --help for the full set of node group options.
{: .alert .alert-info }

#### Install Multus and aws-k8s-cni in the cluster

Install Multus

```bash
kubectl apply -f https://raw.githubusercontent.com/openshift/multus-cni/master/images/multus-daemonset.yml
```

Install `aws-k8s-cni` plugin

```bash
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/v1.6/aws-k8s-cni.yaml
```

#### Add aws-k8s-cni to Multus

Multus uses custom resources to configure different CNI plugins.

Create `NetworkAttachmentDefinition` and add `aws-k8s-cni` plugin configuration.

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

### Demo 

Create a namespace to isolate your demo resources.

```bash
kubectl create namespace calico-multus-demo
```

Use `v1.multus-cni.io/default-network: aws-cni` annotation in pod manifest to attach it to the VPC network.

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

Create another pod using {{site.prodname}} networking.

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

At this point you should be able to browse `awspod` home page using `http://localhost:8001/api/v1/namespaces/calico-multus-demo/services/awspod-service/proxy/` or {% include open-new-window.html text='by clicking here.' url='http://localhost:8001/api/v1/namespaces/calico-multus-demo/services/awspod-service/proxy/' %}.

{% include open-new-window.html text='Pod not reachable by conrol plane.' url='http://localhost:8001/api/v1/namespaces/calico-multus-demo/services/calicopod-service/proxy/' %}


#### Cleanup

Remove demo resources

```bash
kubectl delete namespace calico-multus-demo
```
