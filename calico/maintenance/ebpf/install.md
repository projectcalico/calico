---
title: Install in eBPF mode
description: Install Calico in eBPF mode.
canonical_url: '/maintenance/ebpf/install'
---

### Big picture

Install the eBPF dataplane during the initial installation of {{site.prodname}}.

### Value

{% include content/ebpf-value.md %}

### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **eBPF dataplane**

### Concepts

#### eBPF

eBPF (or "extended Berkeley Packet Filter"), is a technology that allows safe mini programs to be attached to various
low-level hooks in the Linux kernel. eBPF has a wide variety of uses, including networking, security, and tracing. 
You’ll see a lot of non-networking projects leveraging eBPF, but for {{site.prodname}} our focus is on networking, 
and in particular, pushing the networking capabilities of the latest Linux kernels to the limit.

### Before you begin

#### Supported

- x86-64

- Distributions:  

  - Generic or kubeadm
  - kOps
  - OpenShift
  - EKS
  - AKS

- Linux distribution/kernel:

  - Ubuntu 20.04.
  - Red Hat v8.2 with Linux kernel v4.18.0-193 or above (Red Hat have backported the required features to that build).
  - Another [supported distribution]({{site.baseurl}}/getting-started/kubernetes/requirements) with Linux kernel v5.3 or above.

- An underlying network fabric that allows VXLAN traffic between hosts.  In eBPF mode, VXLAN is used to forward Kubernetes NodePort traffic.

#### Not supported

- Other processor architectures.

- Distributions:

  - GKE.  This is because of an incompatibility with the GKE CNI plugin.
  
  - RKE: eBPF mode cannot be enabled at install time because RKE doesn't provide
    a stable address for the API server.  However, by following [these instructions](../../maintenance/ebpf/enabling-ebpf),
    it can be enabled as a post-install step.
  
  - Mirantis Kubernetes Engine (MKE): eBPF mode is incompatible with MKE at this time. The Tigera team is investigating the issue.

- Clusters with some eBPF nodes and some standard dataplane and/or Windows nodes.
- IPv6.
- Host endpoint `doNotTrack` policy (other policy types are supported).
- Floating IPs.
- SCTP (either for policy or services).
- `Log` action in policy rules.
- Tagged VLAN devices.

#### Performance

For best pod-to-pod performance, we recommend using an underlying network that doesn't require Calico to use an overlay.  For example:

- A cluster within a single AWS subnet.
- A cluster using a compatible cloud provider's CNI (such as the AWS VPC CNI plugin).
- An on-prem cluster with BGP peering configured.

If you must use an overlay, we recommend that you use VXLAN, not IPIP.  VXLAN has better performance than IPIP in
eBPF mode due to various kernel optimisations.

### How to

To install in eBPF mode, we recommend using the Tigera Operator to install {{site.prodname}} so these instructions
use the operator.  Installing {{ site.prodname }} normally consists of the following stages, which are covered by the
main installation guides:

* Create a cluster suitable to run {{site.prodname}}.
* Install the Tigera Operator (possibly via a Helm chart), and the associated Custom Resource Definitions.
* Apply a set of Custom Resources to tell the operator what to install.
* Wait for the operator to provision all the associated resources and report back via its status resource.

To install directly in eBPF is very similar; this guide explains the differences:

* [Create a cluster](#create-a-suitable-cluster) suitable to run {{site.prodname}} **with the added requirement that the nodes must use a recent 
  enough kernel**.
* [**Create a config map with the "real" address of the API server.**](#create-kubernetes-service-endpoint-config-map)  This allows the operator to install {{site.prodname}}
  with a direct connection to the API server so that it can take over from `kube-proxy`.
* [Install the Tigera Operator](#install-the-tigera-operator) (possibly via a Helm chart), and the associated Custom Resource Definitions.
* **[Download and tweak the installation Custom Resource](#tweak-and-apply-installation-custom-resources) to tell the operator to use eBPF mode.**
* [Apply a set of Custom Resources](#tweak-and-apply-installation-custom-resources) to tell the operator what to install.
* [Wait for the operator to provision all the associated resources and report back via its status resource](#monitor-the-progress-of-the-installation).
* [Disable kube-proxy or avoid conflicts.](#disable-kube-proxy-or-avoid-conflicts)

These steps are explained in more detail below.

#### Create a suitable cluster

The basic requirement for eBPF mode is to have a recent-enough kernel (see [above](#supported)).  

Select the appropriate tab below for distribution-specific instructions:

{% tabs tab-group:grp1 %}
<label:Generic or kubeadm,active:true>
<%

`kubeadm` supports a number of base OSes; as long as the base OS chosen (such as Ubuntu 20.04) meets the kernel 
requirements, `kubeadm`-provisioned clusters are supported.

Since `kube-proxy` is not required in eBPF mode, you may wish to disable `kube-proxy` at install time.  With `kubeadm`
you can do that by passing the ` --skip-phases=addon/kube-proxy` flag to `kubeadm init`: 

```
kubeadm init --skip-phases=addon/kube-proxy
``` 

%>
<label:kOps>
<%

`kops` supports a number of base OSes; as long as the base OS chosen (such as Ubuntu 20.04 or RHEL 8.2) meets the kernel
requirements, `kops`-provisioned clusters are supported.

Since `kube-proxy` is not required in eBPF mode, you may wish to disable `kube-proxy` at install time.  With `kops` you
can do that by setting the follwing in your `kops` configuration:

```
  kubeProxy:
    enabled: false
```

%>
<label:OpenShift>
<%

OpenShift supports a number of base OSes; as long as the base OS chosen has a recent enough kernel, OpenShift clusters are 
fully supported.  Since Red Hat have backported the eBPF features required by {{site.prodname}} the Red Hat kernel 
version required is lower than the mainline: v4.18.0-193 or above.

%>
<label:AKS>
<%

Azure Kubernetes Service (AKS) supports a number of base OSes.  The most recent Ubuntu 18.04 image has a recent enough
kernel to use with eBPF mode.

AKS does not support disabling `kube-proxy` so it's necessary to tell {{site.prodname}} not to try to clean up 
`kube-proxy`'s iptables rules at a later stage.

%>
<label:EKS>
<%

Amazon's Elastic Kubernetes Service (EKS) supports a number of base OSes for nodes.  At the time of writing, the
default kernel used by Amazon Linux is recent enough to run eBPF mode, as is the Bottlerocket kernel.  The Ubuntu
18.04 image did not have a recent-enough kernel (but that may have changed by the time you read this).

%>
{% endtabs %}

#### Create kubernetes-service-endpoint config map

In eBPF mode, {{site.prodname}} takes over from `kube-proxy`.  This means that, like `kube-proxy`, it needs to be able
to reach the API server _directly_ rather than by using the API server's `ClusterIP`.  To tell {{site.prodname}} how 
to reach the API server we create a `ConfigMap` with the API server's "real" address.  In this guide we do that before
installing the Tigera Operator.  That means that the operator itself can also use the direct connection and hence
it doesn't require `kube-proxy` to be running.

The tabs below explain how to find the "real" address of the API server for a range of distributions.  
**Note:** In all cases it's important that the address used is stable even if your API server is restarted or 
scaled up/down.  If you have multiple API servers, with DNS or other load balancing in front it's important to use 
the address of the load balancer.  This prevents {{site.prodname}} from being disconnected if the API servers IP changes.

{% tabs tab-group:grp1 %}
<label:Generic or kubeadm,active:true>
<%

If you created a cluster manually (for example by using `kubeadm`) then the right address to use depends on whether you
opted for a high-availability cluster with multiple API servers or a simple one-node API server.

* If you opted to set up a high availability cluster then you should use the address of the load balancer that you
  used in front of your API servers.  As noted in the Kubernetes documentation, a load balancer is required for a 
  HA set-up but the precise type of load balancer is not specified.
  
* If you opted for a single control plane node then you can use the address of the control plane node itself.  However,
  it's important that you use a _stable_ address for that node such as a dedicated DNS record, or a static IP address.
  If you use a dynamic IP address (such as an EC2 private IP) then the address may change when the node is restarted
  causing {{ site.prodname }} to lose connectivity to the API server.

%>
<label:kOps>
<%

When using `kops`, `kops` typically sets up a load balancer of some sort in front of the API server.  You should use
the FQDN and port of the API load balancer: `api.internal.<clustername>`.

%>
<label:OpenShift>
<%

OpenShift requires various DNS records to be created for the cluster; one of these is exactly what we need:
`api.<cluster_name>.<base_domain>` should point to the API server or to the load balancer in front of the 
API server. Use that (filling in the `<cluster_name>` and `<base_domain>` as appropriate for your cluster) for the 
`KUBERNETES_SERVICE_HOST` below.  Openshift uses 6443 for the `KUBERNETES_SERVICE_PORT`.

%>
<label:AKS>
<%
For AKS clusters, you should use the FQDN of your API server.  This can be found by running the following command:
```
kubectl cluster-info
```
which should give output similar to the following:
```
Kubernetes master is running at https://mycalicocl-calicodemorg-03a087-36558dbb.hcp.canadaeast.azmk8s.io:443
```
In this example, you would use `mycalicocl-calicodemorg-03a087-36558dbb.hcp.canadaeast.azmk8s.io` for
`KUBERNETES_SERVICE_HOST` and `443` for `KUBERNETES_SERVICE_PORT` when creating the config map.

%>
<label:EKS>
<%
For an EKS cluster, it's important to use the domain name of the EKS-provided load balancer that is in front of the API
server.  This can be found by running the following command:
```
kubectl cluster-info
```
which should give output similar to the following:
```
Kubernetes master is running at https://60F939227672BC3D5A1B3EC9744B2B21.gr7.us-west-2.eks.amazonaws.com
...
```
In this example, you would use `60F939227672BC3D5A1B3EC9744B2B21.gr7.us-west-2.eks.amazonaws.com` for
`KUBERNETES_SERVICE_HOST` and `443` for `KUBERNETES_SERVICE_PORT` when creating the config map.

%>
{% endtabs %}

Create the following config map in the `tigera-operator` namespace using the host and port determined above:

```
kubectl apply -f - <<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: kubernetes-services-endpoint
  namespace: tigera-operator
data:
  KUBERNETES_SERVICE_HOST: "<API server host>"
  KUBERNETES_SERVICE_PORT: "<API server port>"
EOF
```

> **Tip**: If you forget to create the config map before installing the operator you can create it afterwards and
> then wait 60 seconds (for the config map to propagate) before restarting the operator:
> ```
> kubectl delete pod -n tigera-operator -l k8s-app=tigera-operator
> ```
{: .alert .alert-success}

#### Install the Tigera Operator

Follow the steps in the main install guide for your platform to install the Tigera Operator (and possibly the 
Prometheus Operator).  However, **stop** before applying the `custom-resources.yaml`; we'll customise that file
to enable eBPF mode in the next step...

#### Tweak and apply installation Custom Resources

When the main install guide tells you to apply the `custom-resources.yaml`, typically by running `kubectl create` with 
the URL of the file directly, you should instead download the file, so that you can edit it:

```bash
curl -o custom-resources.yaml <url of the file from the main install guide>
```

Edit the file in your editor of choice and find the `Installation` resource, which should be at the top of the file.
To enable eBPF mode, we need to add a new `calicoNetwork` section inside the `spec` of the Installation resource,
including the `linuxDataplane` field.  For EKS Bottlerocket OS only, you should also add the `flexVolumePath` setting 
as shown below. 

For example:

```yaml
# This section includes base Calico Enterprise installation configuration.
# For more information, see: https://docs.tigera.io/master/reference/installation/api#operator.tigera.io/v1.Installation
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  # Added calicoNetwork section with linuxDataplane field
  calicoNetwork:
    linuxDataplane: BPF
    
  # EKS with Bottlerocket as node image only:
  # flexVolumePath: /var/lib/kubelet/plugins
    
  # Install Calico Enterprise
  variant: TigeraSecureEnterprise
  
  # ... remainder of the Installation resource varies by platform ...
```

Then apply the edited file:

```bash
kubectl create -f custom-resources.yaml
```

> **Tip**: If you already created the custom resources, you can switch your cluster over to eBPF mode by updating the
> installation resource.  The operator will automatically roll out the change.
> ```bash
> kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"linuxDataplane":"BPF", "hostPorts":null}}}'
> ```
{: .alert .alert-success}

#### Monitor the progress of the installation

You can monitor progress of the installation with the following command:
```bash
watch kubectl get tigerastatus
```

#### Disable `kube-proxy` (or avoid conflicts)

In eBPF mode, to avoid conflicts with `kube-proxy` it's necessary to either disable `kube-proxy` or to configure 
{{ site.prodname }} not to clean up `kube-proxy`'s iptables rules.  If you didn't disable `kube-proxy` when starting 
your cluster then follow the steps below to avoid conflicts:


{% tabs tab-group:grp1 %}
<label:Generic or kubeadm,active:true>
<%

For a cluster that runs `kube-proxy` in a `DaemonSet` (such as a `kubeadm`-created cluster), you can disable 
`kube-proxy`, reversibly, by adding a node selector to `kube-proxy`'s `DaemonSet` that matches no nodes, for example:

```
kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
```

Then, should you want to start `kube-proxy` again, you can simply remove the node selector.

%>
<label:kOps>
<%

`kops` allows `kube-proxy` to be disabled by setting

```yaml
  kubeProxy:
    enabled: false
```

in its configuration.  You will need to do `kops update cluster` to roll out the change.

%>
<label:OpenShift>
<%

In OpenShift, you can disable `kube-proxy` as follows:

```
kubectl patch networks.operator.openshift.io cluster --type merge -p '{"spec":{"deployKubeProxy": false}}'
```

If you need to re-enable it later:

```
kubectl patch networks.operator.openshift.io cluster --type merge -p '{"spec":{"deployKubeProxy": true}}'
```

%>
<label:AKS>
<%

AKS with Azure CNI does not allow `kube-proxy` to be disabled, `kube-proxy` is deployed by the addon manager, which will reconcile
away any manual changes made to its configuration.  To ensure `kube-proxy` and {{site.prodname}} don't fight, set
the Felix configuration parameter `bpfKubeProxyIptablesCleanupEnabled` to false.  This can be done with
`kubectl` as follows:

```
kubectl patch felixconfiguration.p default --type merge --patch='{"spec": {"bpfKubeProxyIptablesCleanupEnabled": false}}'
```

%>
<label:EKS>
<%

In EKS, you can disable `kube-proxy`, reversibly, by adding a node selector that doesn't match and nodes to 
`kube-proxy`'s `DaemonSet`, for example:

```
kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
```

Then, should you want to start `kube-proxy` again, you can simply remove the node selector.
%>
{% endtabs %}

### Next steps

**Recommended**

- [Learn more about eBPF]({{site.baseurl}}/maintenance/ebpf/use-cases-ebpf)

