---
title: Creating an EKS cluster for eBPF mode
description: Create an EKS cluster with a newer kernel, suitable for eBPF mode.
---

### Big picture

This guide explains how to set up an EKS cluster with a recent-enough Linux kernel to run the eBPF dataplane.  

### Value

By default, EKS uses an older version of the Linux kernel in its base image, which is not compatible with {{site.prodname}}'s 
eBPF mode.  This guide explains how to set up a cluster using a base image with a recent-enough kernel.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **EKS Support**
- **calico/node**
- **eBPF dataplane**

### Concepts

#### eBPF

eBPF (or "extended Berkeley Packet Filter"), is a technology that allows safe mini programs to be attached to various 
low-level hooks in the Linux kernel. eBPF has a wide variety of uses, including networking, security, and tracing.
You’ll see a lot of non-networking projects leveraging eBPF, but for {{site.prodname}} our focus is on networking,
and in particular, pushing the networking capabilities of the latest Linux kernels to the limit.

#### EKS

EKS is Amazon's managed Kubernetes offering.

> **Note**: The EKS docs include instructions for installing {{site.prodname}}. However, those instructions use
> a version of {{site.prodname}} that pre-dates eBPF mode GA.  The instructions below use a pre-release manifest
> in order to install a suitable version of {{site.prodname}}.
{: .alert .alert-info}

### How to

#### Create an eBPF compatible EKS cluster

By default, EKS uses Amazon Linux 2 as its base image for EKS, which does not meet the kernel version requirement for 
eBPF mode.  Below, we give a couple of options for how to get the cluster running with a suitable kernel:


{% tabs tab-group:grp1 %}
<label:Bottlerocket,active:true>
<%

The easiest way to start an EKS cluster that meets eBPF mode's requirements is to use Amazon's 
[Bottlerocket](https://aws.amazon.com/bottlerocket/) OS, instead of the default.  Bottlerocket is a 
container-optimised OS with an emphasis on security; it has a version of the kernel which is compatible with eBPF mode.

* To create a 2-node test cluster with a Bottlerocket node group, run the command below.  It is important to use the config-file
  approach to creating a cluster in order to set the additional IAM permissions for Bottlerocket.

  ```
  eksctl create cluster --config-file - <<EOF
  apiVersion: eksctl.io/v1alpha5
  kind: ClusterConfig
  metadata:
    name: my-calico-cluster
    region: us-west-2
    version: '1.18'
  nodeGroups:
    - name: ng-my-calico-cluster
      instanceType: t3.medium
      minSize: 0
      maxSize: 2
      desiredCapacity: 2
      amiFamily: Bottlerocket
      iam:
        attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
  EOF
  ```

* Install {{site.prodname}} using the following manifest from the AWS VPC CNI project:
  ```bash
  kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/ae02a103b091f38b0aafd0ff6dd0e8f611cf9e67/config/master/calico.yaml
  ```
  
  > **Note**: Due to Bottlerocket's read-only file system, it is not possible to install {{site.prodname}} in 
  > {{site.prodname}} CNI mode at present.
  {: .alert .alert-info}

* [Install `calicoctl`]({{site.baseurl}}/getting-started/clis/calicoctl/install); it is needed for the following step.

* Create a {{site.prodname}} IP pool that matches your VPC subnet and has the `natOutgoing` flag set.
  The IP pool will not be used for IPAM since AWS VPC CNI has its own IPAM, but it will tell {{site.prodname}}
  to SNAT traffic that is leaving the confines of your VPC.
  
  ```
  calicoctl apply -f - <<EOF 
  apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    name: vpc-subnet
  spec:
    cidr: <your VPC subnet>
    natOutgoing: true
    nodeSelector: !all()
  EOF
  ```  
 
%>
<label:Custom AMI>
<%

If you are familiar with the AMI creation process, it is also possible to create a custom AMI based on Ubuntu 20.04, 
which is suitable:

* Create an EKS cluster with a nodeGroup that uses `amiFamily=Ubuntu1804`

* Log into a worker instance with `ssh` and upgrade it to Ubuntu 20.04.

* [Save the instance off as a custom AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html){:target="_blank"} 
  and make a note of the AMI ID

* Delete the EKS cluster.

* Using `eksctl`: start your cluster as normal:
  ```
  eksctl create cluster \
   --name my-calico-cluster \
   --version 1.18 \
   --with-oidc \
   --without-nodegroup
  ```

* To use {{site.prodname}} with the AWS VPC CNI: 

  * install {{site.prodname}} using the following manifest from the AWS VPC CNI project:
    ```bash
    kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/ae02a103b091f38b0aafd0ff6dd0e8f611cf9e67/config/master/calico.yaml
    ```
  
    > **Note**: It's important to use this manifest because the version linked from the
    > [<u>current EKS docs</u>](https://docs.aws.amazon.com/eks/latest/userguide/calico.html) uses a version of {{site.prodname}}
    > that is too old and only has partial support for eBPF mode.
    {: .alert .alert-info}

  * [Install `calicoctl`]({{site.baseurl}}/getting-started/clis/calicoctl/install); it is needed for the following step.

  * Create a {{site.prodname}} IP pool that matches your VPC subnet and has the `natOutgoing` flag set.
    The IP pool will now be used for IPAM since AWS VPC CNI has its own IPAM, but it will tell {{site.prodname}}
    to SNAT traffic that is leaving the confines of your VPC.
  
    ```
    calicoctl apply -f - <<EOF 
    apiVersion: projectcalico.org/v3
    kind: IPPool
    metadata:
      name: vpc-subnet
    spec:
      cidr: <your VPC subnet>
      natOutgoing: true
      nodeSelector: !all()
    EOF
    ```  

* Alternatively, to use {{site.prodname}} networking:

  * Delete the `aws-node` daemon set to disable AWS VPC networking for pods.
    
    ```bash
    kubectl delete daemonset -n kube-system aws-node
    ```
    
  * Install {{site.prodname}}.
    
    ```bash
    kubectl apply -f {{ "/manifests/calico-vxlan.yaml" | absolute_url }}
    ```

* Create a nodegroup, using the AMI ID you noted above.
  * `--node-ami` should be set to the AMI ID of the image built above.
  * `--node-ami-family` should be set to `Ubuntu1804` (despite the upgrade).

  * For example:
    ```
    eksctl create nodegroup \
      --cluster my-calico-cluster \
      --node-type t3.medium \
      --node-ami auto \
      --max-pods-per-node 100 \
      --node-ami-family Ubuntu1804 \
      --node-ami <AMI ID>
    ```

%>
{% endtabs %}

#### Configure {{site.prodname}} to connect directly to the API server
* When configuring {{site.prodname}} to connect to the API server, we need to use the load balanced domain name
  created by EKS.  It can be extracted from `kube-proxy`'s config map by running:
  ```
  kubectl get cm -n kube-system kube-proxy -o yaml | grep server
  ```
  which should show the server name, for example:
  ```
      server: https://d881b853ae9313e00302a84f1e346a77.gr7.us-west-2.eks.amazonaws.com
  ```
  In this example, you would use `d881b853ae9313e00302a84f1e346a77.gr7.us-west-2.eks.amazonaws.com` for `KUBERNETES_SERVICE_HOST`
  and `443` (the default for HTTPS) for `KUBERNETES_SERVICE_PORT` when creating the config map.

  Create the following config map in the `kube-system` namespace using the host and port determined above:

  ```
  kubectl apply -f - <<EOF
  kind: ConfigMap
  apiVersion: v1
  metadata:
    name: kubernetes-services-endpoint
    namespace: kube-system
  data:
    KUBERNETES_SERVICE_HOST: "<API server host>"
    KUBERNETES_SERVICE_PORT: "443"
  EOF
  ```

* Wait 60s for kubelet to pick up the `ConfigMap` (see Kubernetes [issue #30189](https://github.com/kubernetes/kubernetes/issues/30189){:target="_blank"}); then, restart the {{site.prodname}} pods to pick up the change:

  ```
  kubectl delete pod -n kube-system -l k8s-app=calico-node
  ```

  And, if using Typha and/or calico-kube-controllers (if you're not sure if you're running these, run the commands
  anyway, they will fail with "No resources found" if the pods aren't present):
  ```
  kubectl delete pod -n kube-system -l k8s-app=calico-typha
  kubectl delete pod -n kube-system -l k8s-app=calico-kube-controllers
  ```

* Confirm that pods restart and reach the `Running` state with the following command:

  ```
  watch "kubectl get pods -n kube-system | grep calico"
  ```

  You can verify that the change was picked up by checking the logs of one of the {{ site.nodecontainer }} pods.

  ```
  kubectl get po -n kube-system -l k8s-app=calico-node
  ```

  Should show one or more pods:

  ```
  NAME                                       READY   STATUS    RESTARTS   AGE
  {{site.noderunning}}-d6znw                          1/1     Running   0          48m
  ...
  ```

  Then, to search the logs, choose a pod and run:

  ```
  kubectl logs -n kube-system <pod name> | grep KUBERNETES_SERVICE_HOST
  ```

  You should see the following log, with the correct `KUBERNETES_SERVICE_...` values.

  ```
  2020-08-26 12:26:29.025 [INFO][7] daemon.go 182: Kubernetes server override env vars. KUBERNETES_SERVICE_HOST="172.16.101.157" KUBERNETES_SERVICE_PORT="6443"
  ```

#### Disable kube-proxy

In eBPF mode, {{site.prodname}} replaces `kube-proxy` so it wastes resources to run both.  To disable `kube-proxy` reversibly, we recommend adding a node selector to `kube-proxy`'s `DaemonSet` that matches no nodes, for example:

```
kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
```

Then, should you want to start `kube-proxy` again, you can simply remove the node selector.

#### Enable eBPF mode

To enable eBPF mode, change the Felix configuration parameter `BPFEnabled` to `true`.  This can be done with `calicoctl`, as follows:

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfEnabled": true}}'
```

Enabling eBPF node can disrupt existing workload connections.  After enabling eBPF mode you may need to restart
workload pods in order for them to restart connections.  In particular, it's a good idea to restart `kube-dns`
since its connection to the API server can be disrupted:

```
kubectl delete pod -n kube-system -l k8s-app=kube-dns
```

#### How to disable eBPF mode

Follow these steps if you want to switch from Calico's eBPF dataplane back to standard Linux networking:

1. Disable Calico eBPF mode:

   ```
   calicoctl patch felixconfiguration default --patch='{"spec": {"bpfEnabled": false}}'
   ```

1. If you disabled `kube-proxy`, re-enable it (for example, by removing the node selector added above).
   ```
   kubectl patch ds -n kube-system kube-proxy --type merge -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": null}}}}}'
   ```

1. Monitor existing workloads to make sure they reestablish connections.

### Send us feedback

We would love to hear about your experience with the eBPF dataplane.  Please don’t hesitate to connect with us via the {% include open-new-window.html text='Calico Users Slack' url='http://slack.projectcalico.org/' %} group.
