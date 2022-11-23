---
title: Enable the eBPF dataplane
description: Step-by-step instructions for enabling the eBPF dataplane.
canonical_url: '/maintenance/ebpf/enabling-ebpf'
---

### Big picture

Enable the eBPF dataplane on an existing cluster.

### Value 

{% include content/ebpf-value.md %}

### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **eBPF dataplane**

### Concepts

#### eBPF

eBPF (or "extended Berkeley Packet Filter"), is a technology that allows safe mini programs to be attached to various low-level hooks in the Linux kernel. eBPF has a wide variety of uses, including networking, security, and tracing. You’ll see a lot of non-networking projects leveraging eBPF, but for {{site.prodname}} our focus is on networking, and in particular, pushing the networking capabilities of the latest Linux kernels to the limit.

### Before you begin

#### Supported

- x86-64
- ARM64 (community supported, not actively regression tested by the {{site.prodname}} team)

- Distributions:

  - Generic or kubeadm
  - kOps
  - OpenShift
  - EKS
  - AKS with limitations:
    - [AKS with Azure CNI and Calico network policy](../../getting-started/kubernetes/managed-public-cloud/aks#install-aks-with-{{site.prodnamedash}}-for-network-policy) works, but it is not possible to disable kube-proxy resulting in wasted resources and suboptimal performance.
    - [AKS with {{site.prodname}} networking](../../getting-started/kubernetes/managed-public-cloud/aks#install-aks-with-{{site.prodnamedash}}-networking) is in testing with the eBPF dataplane. This should be a better solution overall but, at time of writing, the testing was not complete.
  - RKE (RKE2 recommended because it supports disabling `kube-proxy`)

- Linux distribution/kernel:

  - Ubuntu 20.04.
  - Red Hat v8.2 with Linux kernel v4.18.0-193 or above (Red Hat have backported the required features to that build).
  - Another [supported distribution]({{site.baseurl}}/getting-started/kubernetes/requirements) with Linux kernel v5.3 or above.  Kernel v5.8 or above with CO-RE enabled is recommended for better performance. 

- An underlying network fabric that allows VXLAN traffic between hosts.  In eBPF mode, VXLAN is used to forward Kubernetes NodePort traffic.

#### Not supported

- Other processor architectures.

- Distributions:

  - GKE.  This is because of an incompatibility with the GKE CNI plugin.

- Clusters with some eBPF nodes and some standard dataplane and/or Windows nodes.
- IPv6.
- Floating IPs.
- SCTP (either for policy or services). This is due to lack of kernel support for the SCTP checksum in BPF.
- `Log` action in policy rules. This is because the `Log` action maps to the iptables `LOG` action and BPF programs cannot access that log.
- VLAN-based traffic.

#### Performance

For best pod-to-pod performance, we recommend using an underlying network that doesn't require Calico to use an overlay.  For example:

- A cluster within a single AWS subnet.
- A cluster using a compatible cloud provider's CNI (such as the AWS VPC CNI plugin).
- An on-prem cluster with BGP peering configured.

If you must use an overlay, we recommend that you use VXLAN, not IPIP.  VXLAN has much better performance than IPIP in
eBPF mode due to various kernel optimisations.

### How to

- [Verify that your cluster is ready for eBPF mode](#verify-that-your-cluster-is-ready-for-ebpf-mode)
- [Configure {{site.prodname}} to talk directly to the API server](#configure-{{site.prodnamedash}}-to-talk-directly-to-the-api-server)
- [Configure kube-proxy](#configure-kube-proxy)
- [Enable eBPF mode](#enable-ebpf-mode)
- [Try out DSR mode](#try-out-dsr-mode)
- [Reversing the process](#reversing-the-process)

#### Verify that your cluster is ready for eBPF mode

This section explains how to make sure your cluster is suitable for eBPF mode.

To check that the kernel on a node is suitable, you can run

```bash
uname -rv
```

The output should look like this:

```
5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020
```

In this case the kernel version is v5.4, which is suitable.

On Red Hat-derived distributions, you may see something like this:
```
4.18.0-193.el8.x86_64 (mockbuild@x86-vm-08.build.eng.bos.redhat.com)
```
Since the Red Hat kernel is v4.18 with at least build number 193, this kernel is suitable.

#### Configure {{site.prodname}} to talk directly to the API server

In eBPF mode, {{site.prodname}} implements Kubernetes service networking directly (rather than relying on `kube-proxy`).
Of course, this makes it highly desirable to disable `kube-proxy` when running in eBPF mode in order to save resources
and avoid confusion over which component is handling services.

To be able to disable `kube-proxy`, {{site.prodname}} needs to communicate to the API server _directly_ rather than 
going through `kube-proxy`.  To make _that_ possible, we need to find a persistent, static way to reach the API server.
The best way to do that varies by Kubernetes distribution:

* If you created a cluster manually (for example by using `kubeadm`) then the right address to use depends on whether you
  opted for a high-availability cluster with multiple API servers or a simple one-node API server.

  * If you opted to set up a high availability cluster then you should use the address of the load balancer that you
    used in front of your API servers.  As noted in the Kubernetes documentation, a load balancer is required for a
    HA set-up but the precise type of load balancer is not specified.
    
  * If you opted for a single control plane node then you can use the address of the control plane node itself.  However,
    it's important that you use a _stable_ address for that node such as a dedicated DNS record, or a static IP address.
    If you use a dynamic IP address (such as an EC2 private IP) then the address may change when the node is restarted
    causing {{ site.prodname }} to lose connectivity to the API server.
    
* `kops` typically sets up a load balancer of some sort in front of the API server.  You should use
  the FQDN and port of the API load balancer, for example `api.internal.<clustername>` as the `KUBERNETES_SERVICE_HOST` 
  below and 443 as the `KUBERNETES_SERVICE_PORT`.
  
* OpenShift requires various DNS records to be created for the cluster; one of these is exactly what we need:
  `api-int.<cluster_name>.<base_domain>` should point to the API server or to the load balancer in front of the
  API server. Use that (filling in the `<cluster_name>` and `<base_domain>` as appropriate for your cluster) for the
  `KUBERNETES_SERVICE_HOST` below.  Openshift uses 6443 for the `KUBERNETES_SERVICE_PORT`.
  
* For AKS and EKS clusters you should use the FQDN of the API server's load balancer.  This can be found with
  ```
  kubectl cluster-info 
  ```
  which gives output like the following:
  ```
  Kubernetes master is running at https://60F939227672BC3D5A1B3EC9744B2B21.gr7.us-west-2.eks.amazonaws.com
  ...
  ```
  In this example, you would use `60F939227672BC3D5A1B3EC9744B2B21.gr7.us-west-2.eks.amazonaws.com` for
  `KUBERNETES_SERVICE_HOST` and `443` for `KUBERNETES_SERVICE_PORT` when creating the config map.
  
* MKE and Rancher neither allow `kube-proxy` to be disabled nor provide a stable address for the 
  API server that is suitable for the next step.  The best option on these platforms is to 
  
  * Let {{site.prodname}} connect to the API server as through `kube-proxy` (by skipping the step below to create the
    `kubernetes-services-endpoint` config map).
    
  * Then, follow the instructions in [Avoiding conflicts with kube-proxy](#avoiding-conflicts-with-kube-proxy) below, 
    or connectivity will fail when eBPF mode is enabled.

**The next step depends on whether you installed {{site.prodname}} using the operator, or a manifest:**

{% tabs tab-group:grp1 %}
<label:Operator,active:true>
<%

If you installed {{site.prodname}} using the operator, create the following config map in the `tigera-operator` namespace using the host and port determined above:

```
kind: ConfigMap
apiVersion: v1
metadata:
  name: kubernetes-services-endpoint
  namespace: tigera-operator
data:
  KUBERNETES_SERVICE_HOST: "<API server host>"
  KUBERNETES_SERVICE_PORT: "<API server port>"
```
The operator will pick up the change to the config map automatically and do a rolling update of {{site.prodname}} to pass on the change.  Confirm that pods restart and then reach the `Running` state with the following command:

```
watch kubectl get pods -n calico-system
```

If you do not see the pods restart then it's possible that the `ConfigMap` wasn't picked up (sometimes Kubernetes is slow to propagate `ConfigMap`s (see Kubernetes [issue #30189](https://github.com/kubernetes/kubernetes/issues/30189){:target="_blank"})). You can try restarting the operator.

%>
<label:Manifest>
<%

If you installed {{site.prodname}} using a manifest, create the following config map in the `kube-system` namespace using the host and port determined above:

```
kind: ConfigMap
apiVersion: v1
metadata:
  name: kubernetes-services-endpoint
  namespace: kube-system
data:
  KUBERNETES_SERVICE_HOST: "<API server host>"
  KUBERNETES_SERVICE_PORT: "<API server port>"
```

Wait 60s for kubelet to pick up the `ConfigMap` (see Kubernetes [issue #30189](https://github.com/kubernetes/kubernetes/issues/30189){:target="_blank"}); then, restart the {{site.prodname}} pods to pick up the change:

```
kubectl delete pod -n kube-system -l k8s-app=calico-node
kubectl delete pod -n kube-system -l k8s-app=calico-kube-controllers
```

And, if using Typha:

```
kubectl delete pod -n kube-system -l k8s-app=calico-typha
```

Confirm that pods restart and then reach the `Running` state with the following command:

```
watch "kubectl get pods -n kube-system | grep calico"
```

You can verify that the change was picked up by checking the logs of one of the  {{ site.nodecontainer }} pods.

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

%>
{% endtabs %}

#### Configure kube-proxy

In eBPF mode {{site.prodname}} replaces `kube-proxy` so it wastes resources (and reduces performance) to run both.  
This section explains how to disable `kube-proxy` in some common environments.

##### Clusters that run `kube-proxy` with a `DaemonSet` (such as `kubeadm`)

For a cluster that runs `kube-proxy` in a `DaemonSet` (such as a `kubeadm`-created cluster), you can disable `kube-proxy` reversibly by adding a node selector to `kube-proxy`'s `DaemonSet` that matches no nodes, for example:

```
kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
```

Then, should you want to start `kube-proxy` again, you can simply remove the node selector.

> **Note**: This approach is not suitable for AKS with Azure CNI since that platform makes use of the Kubernetes add-on manager.
> the change will be reverted by the system.  For AKS, you should follow [Avoiding conflicts with kube-proxy](#avoiding-conflicts-with-kube-proxy)
> below.
{: .alert .alert-info}

##### OpenShift

If you are running OpenShift, you can disable `kube-proxy` as follows:

```
kubectl patch networks.operator.openshift.io cluster --type merge -p '{"spec":{"deployKubeProxy": false}}'
```

To re-enable it:

```
kubectl patch networks.operator.openshift.io cluster --type merge -p '{"spec":{"deployKubeProxy": true}}'
```

#### Avoiding conflicts with kube-proxy

If you cannot disable `kube-proxy` (for example, because it is managed by your Kubernetes distribution), then you *must* change Felix configuration parameter `BPFKubeProxyIptablesCleanupEnabled` to `false`.  This can be done with `kubectl` as follows:

```
kubectl patch felixconfiguration.p default --patch='{"spec": {"bpfKubeProxyIptablesCleanupEnabled": false}}'
```

If both `kube-proxy` and `BPFKubeProxyIptablesCleanupEnabled` is enabled then `kube-proxy` will write its iptables rules and Felix will try to clean them up resulting in iptables flapping between the two.

#### Enable eBPF mode

**The next step depends on whether you installed {{site.prodname}} using the operator, or a manifest:**

{% tabs tab-group:grp2 %}
<label:Operator,active:true>
<%

To enable eBPF mode, change the `spec.calicoNetwork.linuxDataplane` parameter in the operator's `Installation` 
resource to `"BPF"`; you must also clear the `hostPorts` setting because host ports are not supported in BPF mode:

```bash
kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"linuxDataplane":"BPF", "hostPorts":null}}}'
```

> **Note**: the operator rolls out the change with a rolling update which means that some nodes will be in eBPF mode
> before others.  This can disrupt the flow of traffic through node ports.  We plan to improve this in an upcoming release
> by having the operator do the update in two phases.
{: .alert .alert-info}

%>
<label:Manifest>
<%

If you installed {{site.prodname}} using a manifest, change Felix configuration parameter  `BPFEnabled` to `true`.  This can be done with `calicoctl`, as follows:

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfEnabled": true}}'
```

%>

{% endtabs %}

When enabling eBPF mode, pre-existing connections continue to use the non-BPF datapath; such connections should
not be disrupted, but they do not benefit from eBPF mode’s advantages.

#### Try out DSR mode

Direct return mode skips a hop through the network for traffic to services (such as node ports) from outside the cluster.  This reduces latency and CPU overhead but it requires the underlying network to allow nodes to send traffic with each other's IPs.  In AWS, this requires all your nodes to be in the same subnet and for the source/dest check to be disabled.

DSR mode is disabled by default; to enable it, set the `BPFExternalServiceMode` Felix configuration parameter to `"DSR"`.  This can be done with `calicoctl`:

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfExternalServiceMode": "DSR"}}'
```

To switch back to tunneled mode, set the configuration parameter to `"Tunnel"`:

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfExternalServiceMode": "Tunnel"}}'
```

Switching external traffic mode can disrupt in-progress connections.

#### Reversing the process

To revert to standard Linux networking:

1. (Depending on whether you installed Calico with the operator or with a manifest) reverse the changes to the operator's `Installation` or the `FelixConfiguration` resource:

   ```bash
   kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"linuxDataplane":"Iptables"}}}'
   ```

   or:

   ```
   calicoctl patch felixconfiguration default --patch='{"spec": {"bpfEnabled": false}}'
   ```

1. If you disabled `kube-proxy`, re-enable it (for example, by removing the node selector added above).
   ```
   kubectl patch ds -n kube-system kube-proxy --type merge -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": null}}}}}'
   ```

1. Since disabling eBPF mode is disruptive to existing connections, monitor existing workloads to make sure they re-establish any connections that were disrupted by the switch.
