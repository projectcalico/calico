---
title: Enable the eBPF dataplane 
description: Step-by-step instructions for enabling the eBPF dataplane.
---

### Big picture

This guide explains how to enable the eBPF dataplane; a high-performance alternative to the standard (iptables based) dataplane for both {{site.prodname}} and kube-proxy.

### Value

The eBPF dataplane mode has several advantages over standard linux networking pipeline mode:

* It scales to higher throughput.
* It uses less CPU per GBit.
* It has native support for Kubernetes services (without needing kube-proxy) that:

  * Reduces first packet latency for packets to services.
  * Preserves external client source IP addresses all the way to the pod.
  * Supports DSR (Direct Server Return) for more efficient service routing.
  * Uses less CPU than kube-proxy to keep the dataplane in sync.

To learn more and see performance metrics from our test environment, see the blog, {% include open-new-window.html text='Introducing the Calico eBPF dataplane' url='https://www.projectcalico.org/introducing-the-calico-ebpf-dataplane/' %}.

eBPF mode currently has some limitations relative to the standard Linux pipeline mode:

- eBPF mode does not yet support IPv6.
- eBPF mode does not yet support host endpoints, or, their associated policy types.
- Switching to and from eBPF mode is disruptive to existing workload connections.  Workloads that do not detect and recover from connection loss may need to be restarted.
- Hybrid clusters (with some eBPF nodes and some standard dataplane nodes) are not supported.  (In such a cluster, NodePort traffic from eBPF nodes to non-eBPF nodes will be dropped.)

### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **eBPF dataplane**

### Concepts

#### eBPF

eBPF (or "extended Berkeley Packet Filter"), is a technology that allows safe mini programs to be attached to various low-level hooks in the Linux kernel. eBPF has a wide variety of uses, including networking, security, and tracing. You’ll see a lot of non-networking projects leveraging eBPF, but for {{site.prodname}} our focus is on networking, and in particular, pushing the networking capabilities of the latest Linux kernels to the limit.

### Before you begin...

eBPF mode has the following pre-requisites:

- A supported Linux distribution:
  
  - Ubuntu 20.04.
  - Red Hat v8.2 with Linux kernel v4.18.0-193 or above (Red Hat have backported the required features to that build).
  - Another [supported distribution]({{site.baseurl}}/getting-started/kubernetes/requirements) with Linux kernel v5.3 or above.
    
  If {{site.prodname}} does not detect a compatible kernel, {{site.prodname}} will emit a warning and fall back to standard linux networking.
  
- On each node, the BPF filesystem must be mounted at `/sys/fs/bpf`.  This is required so that the BPF filesystem persists when {{site.prodname}} is restarted.  (If the filesystem does not persist then pods will temporarily lose connectivity when {{site.prodname}} is restarted.)
- For best pod-to-pod performance, an underlying network that doesn't require Calico to use an overlay.  For example:
 
  - A cluster within a single AWS subnet.
  - A cluster using a compatible cloud provider's CNI (such as the AWS VPC CNI plugin).
  - An on-prem cluster with BGP peering configured.
  
- The underlying network must be configured to allow VXLAN packets between {{site.prodname}} hosts.  In eBPF mode, VXLAN is used to forward traffic to Kubernetes NodePorts, while preserving source IP.
- A stable way to address the Kubernetes API server. Since eBPF mode takes over from kube-proxy, {{site.prodname}} needs a way to reach the API server directly.
- The base [requirements]({{site.baseurl}}/getting-started/kubernetes/requirements) also apply.

> **Note**: The default kernel used by EKS is not compatible with eBPF mode.  If you wish to try eBPF mode with EKS, follow [these instructions](./ebpf-and-eks).
{: .alert .alert-info}

### How to

- [Verify that your cluster is ready for eBPF mode](#verify-that-your-cluster-is-ready-for-ebpf-mode)
- [Configure {{site.prodname}} to talk directly to the API server](#configure-{{site.prodnamedash}}-to-talk-directly-to-the-api-server)
- [Configure kube-proxy](#configure-kube-proxy)
- [Enable eBPF mode](#enable-ebpf-mode)
- [Try out DSR mode](#try-out-dsr-mode)
- [Reversing the process](#reversing-the-process)

#### Verify that your cluster is ready for eBPF mode

This section explains how to make sure your cluster is suitable for eBPF mode.

1. To check that the kernel on a node is suitable, you can run 

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
   
1. To verify that the BPF filesystem is mounted, on the host, you can run the following command:

   ```
   mount | grep "/sys/fs/bpf"
   ```
   
   If the BPF filesystem is mounted, you should see:
   
   ```
   none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
   ```
   
   If you see no output, then the BPF filesystem is not mounted; consult the documentation for your OS distribution to see how to make sure the file system is mounted at boot in its standard location  /sys/fs/bpf.  This may involve editing `/etc/fstab` or adding a `systemd` unit, depending on your distribution. If the file system is not mounted on the host then eBPF mode will work normally until {{site.prodname}} is restarted, at which point workload netowrking will be disrupted for several seconds.
   
#### Configure {{site.prodname}} to talk directly to the API server
   
In eBPF mode, {{site.prodname}} implements Kubernetes service networking directly (rather than relying on `kube-proxy`).  This means that, like `kube-proxy`,  {{site.prodname}} must connect _directly_ to the Kubernetes API server rather than via the API server's ClusterIP.

First, make a note of the address of the API server:

   * If you have a single API server, you can use its IP address and port.  The IP can be found by running:
   
     ```
     kubectl get endpoints kubernetes -o wide
     ```
     
     The output should look like the following, with a single IP address and port under "ENDPOINTS":
     
     ```
     NAME         ENDPOINTS             AGE
     kubernetes   172.16.101.157:6443   40m
     ```
     
     If there are multiple entries under "ENDPOINTS" then your cluster must have more than one API server.  In that case, you should try to determine the load balancing approach used by your cluster and use the appropriate option below.
     
   * If using DNS load balancing (as used by `kops`), use the FQDN and port of the API server `api.internal.<clustername>`.
   * If you have multiple API servers with a load balancer in front, you should use the IP and port of the load balancer.


The next step depends on whether you installed {{site.prodname}} using the operator, or a manifest:

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

Then, restart the operator to pick up the change:

```
kubectl delete pod -n tigera-operator -l k8s-app=tigera-operator
```

The operator will then do a rolling update of {{site.prodname}} to pass on the change.  Confirm that pods restart and then reach the `Running` state with the following command:

```
watch kubectl get pods -n calico-system
```

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

Wait 60s for kubelet to pick up the `ConfigMap` (see Kubernetes [issue #30189](https://github.com/kubernetes/kubernetes/issues/30189)); then, restart the {{site.prodname}} pods to pick up the change:

```
kubectl delete pod -n kube-system -l k8s-app=calico-node
```

And, if using Typha:

```
kubectl delete pod -n kube-system -l k8s-app=calico-typha
```

Confirm that pods restart and then reach the `Running` state with the following command:

```
watch "kubectl get pods -n kube-system | grep calico"
```

%>
{% endtabs %}

#### Configure kube-proxy

In eBPF mode {{site.prodname}} replaces `kube-proxy` so it wastes resources to run both.  To disable `kube-proxy` reversibly, we recommend adding a node selector to `kube-proxy`'s `DaemonSet` that matches no nodes, for example: 

```
kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
```

Then, should you want to start `kube-proxy` again, you can simply remove the node selector.

If you choose not to disable `kube-proxy` (for example, because it is managed by your Kubernetes distribution), then you *must* change Felix configuration parameter `BPFKubeProxyIptablesCleanupEnabled` to `false`.  This can be done with `calicoctl` as follows:

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfKubeProxyIptablesCleanupEnabled": false}}'
```

If both `kube-proxy` and `BPFKubeProxyIptablesCleanupEnabled` is enabled then `kube-proxy` will write its iptables rules and Felix will try to clean them up resulting in iptables flapping between the two. 

#### Enable eBPF mode

To enable eBPF mode, change Felix configuration parameter  `BPFEnabled` to `true`.  This can be done with `calicoctl`, as follows:

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfEnabled": true}}'
```

Enabling eBPF node can disrupt existing workload connections.  After enabling eBPF mode you may need to restart workload pods in order for them to restart connections. 

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

1. Disable Calico eBPF mode:

   ```
   calicoctl patch felixconfiguration default --patch='{"spec": {"bpfEnabled": false}}'
   ```

1. If you disabled `kube-proxy`, re-enable it (for example, by removing the node selector added above).

1. Monitor existing workloads to make sure they re-establish any connections disrupted by the switch.

### Send us feedback

The eBPF dataplane is still fairly new, and we want to hear about your experience.  Please don’t hesitate to connect with us via the {% include open-new-window.html text='Calico Users Slack' url='http://slack.projectcalico.org/' %} group.
