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
> a version of {{site.prodname}} that pre-dates eBPF mode GA.  The instructions below use the operator to install
> the current version of {{site.prodname}}.
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
* Install the Tigera operator:
  ```
  kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
  ```

  > **Note**: Do not use the manifests from the [<u>current EKS docs</u>](https://docs.aws.amazon.com/eks/latest/userguide/calico.html)
  > because they reference an older version of Calico, which does not have the latest eBPF fixes.
  >
  > It's important to use the operator to install {{site.prodname}}, not a "manifest" install.  The "manifest" installs
  > are not specialised for EKS (but the operator knows how to customise the installation for EKS).
  {: .alert .alert-info}

* Using `kubectl`, apply the following [`Installation` resource]({{site.url}}/{{page.version}}/reference/installation/api#operator.tigera.io/v1.Installation) to tell the operator to install {{site.prodname}}; note the `flexVolumePath` tweak, which is needed for Bottlerocket.

  ```
  apiVersion: operator.tigera.io/v1
  kind: Installation
  metadata:
    name: default
  spec:
    cni:
      type: AmazonVPC
    flexVolumePath: /var/lib/kubelet/plugins
    # Enables provider-specific settings required for compatibility.
    kubernetesProvider: EKS
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

* Using `eksctl`: start your cluster without an initial node group; this allows for customising the CNI configuration before
  it is rolled out:
  
  ```
  eksctl create cluster \
   --name my-calico-cluster \
   --version 1.18 \
   --with-oidc \
   --without-nodegroup
  ```

* Install the Tigera operator:
  ```
  kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
  ```

  > **Note**: Do not use the manifests from the [<u>current EKS docs</u>](https://docs.aws.amazon.com/eks/latest/userguide/calico.html)
  > because they reference an older version of Calico, which does not support eBPF mode.
  >
  > It's important to use the operator to install {{site.prodname}}, not a "manifest" install.  The "manifest" installs
  > are not specialised for EKS (but the operator knows how to customise the installation for EKS).
  {: .alert .alert-info}
  
* To use {{site.prodname}} with the AWS VPC CNI: 

  * Using `kubectl`, apply the following [`Installation` resource]({{site.url}}/{{page.version}}/reference/installation/api#operator.tigera.io/v1.Installation) to tell   the operator to install {{site.prodname}}.

    ```
    apiVersion: operator.tigera.io/v1
    kind: Installation
    metadata:
      name: default
    spec:
      cni:
        type: AmazonVPC
      # Enables provider-specific settings required for compatibility.
      kubernetesProvider: EKS
    ```

* Alternatively, to use {{site.prodname}} networking:

  * Delete the `aws-node` daemon set to disable AWS VPC networking for pods.
    
    ```bash
    kubectl delete daemonset -n kube-system aws-node
    ```
  * Using `kubectl`, apply the following [`Installation` resource]({{site.url}}/{{page.version}}/reference/installation/api#operator.tigera.io/v1.Installation) to tell   the operator to install {{site.prodname}}.  Modify the IP pool CIDR to avoid any clash with your VPC network:

    ```
    apiVersion: operator.tigera.io/v1
    kind: Installation
    metadata:
      name: default
    spec:
      # Configures Calico networking.
      calicoNetwork:
        # Note: The ipPools section cannot be modified post-install.
        ipPools:
        - blockSize: 26
          cidr: 192.168.0.0/16
          encapsulation: VXLANCrossSubnet
          natOutgoing: Enabled
          nodeSelector: all()
      cni:
        type: Calico
      # Enables provider-specific settings required for compatibility.
      kubernetesProvider: EKS
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

When configuring {{site.prodname}} to connect to the API server, we need to use the load balanced domain name 
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

Since we used the operator to install {{site.prodname}}, create the following config map in the 
`tigera-operator` namespace using the host and port determined above:

```
kubectl apply -f - <<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: kubernetes-services-endpoint
  namespace: tigera-operator
data:
  KUBERNETES_SERVICE_HOST: "<API server host>"
  KUBERNETES_SERVICE_PORT: "443"
EOF
```

Wait 60s for kubelet to pick up the `ConfigMap` (see Kubernetes [issue #30189](https://github.com/kubernetes/kubernetes/issues/30189){:target="_blank"}); then, restart the operator to pick up the change:

```
kubectl delete pod -n tigera-operator -l k8s-app=tigera-operator
```

#### Disable kube-proxy

In eBPF mode, {{site.prodname}} replaces `kube-proxy` so it wastes resources to run both.  To disable `kube-proxy` reversibly, we recommend adding a node selector to `kube-proxy`'s `DaemonSet` that matches no nodes, for example:

```
kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
```

Then, should you want to start `kube-proxy` again, you can simply remove the node selector.

#### Enable eBPF mode

To enable eBPF mode, change the `spec.calicoNetwork.linuxDataplane` parameter in
the operator's `Installation` resource to `"BPF"`; you must also clear the hostPorts setting because host ports are not supported in BPF mode:

```bash
kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"linuxDataplane":"BPF", "hostPorts":null}}}'
```

> **Note**: the operator rolls out the change with a rolling update which means that some nodes will be in eBPF mode
> before others.  This can disrupt the flow of traffic through node ports.  We plan to improve this in an upcoming release
> by having the operator do the update in two phases.
{: .alert .alert-info}

### How to disable eBPF mode

Follow these steps if you want to switch from Calico's eBPF dataplane back to standard Linux networking:

* Revert the changes to the operator's installation resource:

  ```bash
  kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"linuxDataplane":"Iptables"}}}'
  ```

* If you disabled `kube-proxy`, re-enable it (for example, by removing the node selector added above).
  ```
  kubectl patch ds -n kube-system kube-proxy --type merge -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": null}}}}}'
  ```

* Since disabling eBPF mode is disruptive, monitor existing workloads to make sure they reestablish connections.

### Send us feedback

We would love to hear about your experience with the eBPF dataplane.  Please don’t hesitate to connect with us via the {% include open-new-window.html text='Calico Users Slack' url='http://slack.projectcalico.org/' %} group.
