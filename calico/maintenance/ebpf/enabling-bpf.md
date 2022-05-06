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

### Limitations

eBPF mode currently has some limitations relative to the standard Linux pipeline mode:

- eBPF mode supports x86-64 and arm64. (For arm64, the support was added from version 3.21.4+)
- eBPF mode does not yet support IPv6.
- When enabling eBPF mode, pre-existing connections continue to use the non-BPF datapath; such connections should not be disrupted, but they do not benefit from eBPF mode's advantages.
- Disabling eBPF mode _is_ disruptive; connections that were handled through the eBPF dataplane may be broken and services that do not detect and recover may need to be restarted.
- Hybrid clusters (with some eBPF nodes and some standard dataplane nodes) are not supported.  (In such a cluster, NodePort traffic from eBPF nodes to non-eBPF nodes will be dropped.)  This includes clusters with Windows nodes.
- eBPF mode does not support floating IPs.
- eBPF mode does not support SCTP, either for policy or services.
- eBPF mode requires that node  [IP autodetection]({{site.baseurl}}/networking/ip-autodetection) is enabled even in environments where {{site.prodname}} CNI and BGP are not in use.  In eBPF mode, the node IP is used to originate VXLAN packets when forwarding traffic from external sources to services.
- eBPF mode does not support the "Log" action in policy rules.

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

    - Ubuntu 20.04 (or Ubuntu 18.04.4+, which has an updated kernel).
    - Red Hat v8.2 with Linux kernel v4.18.0-193 or above (Red Hat have backported the required features to that build).
    - Another [supported distribution]({{site.baseurl}}/getting-started/kubernetes/requirements) with Linux kernel v5.3 or above.

  If {{site.prodname}} does not detect a compatible kernel, {{site.prodname}} will emit a warning and fall back to standard linux networking.

- On each node, the BPF filesystem must be mounted at `/sys/fs/bpf`.  This is required so that the BPF filesystem persists
  when {{site.prodname}} is restarted.  If the filesystem does not persist then pods will temporarily lose connectivity when
  {{site.prodname}} is restarted and host endpoints may be left unsecured (because their attached policy program will be
  discarded).
- For best pod-to-pod performance, an underlying network that doesn't require Calico to use an overlay.  For example:

    - A cluster within a single AWS subnet.
    - A cluster using a compatible cloud provider's CNI (such as the AWS VPC CNI plugin).
    - An on-prem cluster with BGP peering configured.

  If you must use an overlay, we recommend that you use VXLAN, not IPIP.  VXLAN has much better performance than IPIP in
  eBPF mode due to various kernel optimisations.

- The underlying network must be configured to allow VXLAN packets between {{site.prodname}} hosts (even if you normally
  use IPIP or non-overlay for Calico traffic).  In eBPF mode, VXLAN is used to forward Kubernetes NodePort traffic,
  while preserving source IP.  eBPF mode honours the Felix `VXLANMTU` setting (see [Configuring MTU]({{ site.baseurl }}/networking/mtu)).
- A stable way to address the Kubernetes API server. Since eBPF mode takes over from kube-proxy, {{site.prodname}}
  needs a way to reach the API server directly.
- The base [requirements]({{site.baseurl}}/getting-started/kubernetes/requirements) also apply.

### How to

- [Verify that your cluster is ready for eBPF mode](#verify-that-your-cluster-is-ready-for-ebpf-mode)
- [Configure {{site.prodname}} to talk directly to the API server](#configure-{{site.prodnamedash}}-to-talk-directly-to-the-api-server)
- [Configure kube-proxy](#configure-kube-proxy)
- [Configure data interface](#configure-data-interface)
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

   If you see no output, then the BPF filesystem is not mounted; consult the documentation for your OS distribution to see how to make sure the file system is mounted at boot in its standard location  /sys/fs/bpf.  This may involve editing `/etc/fstab` or adding a `systemd` unit, depending on your distribution. If the file system is not mounted on the host then eBPF mode will work normally until {{site.prodname}} is restarted, at which point workload networking will be disrupted for several seconds.

   If your distribution uses `systemd`, you can refer to the following settings:

   ```
   cat <<EOF | sudo tee /etc/systemd/system/sys-fs-bpf.mount
   [Unit]
   Description=BPF mounts
   DefaultDependencies=no
   Before=local-fs.target umount.target
   After=swap.target

   [Mount]
   What=bpffs
   Where=/sys/fs/bpf
   Type=bpf
   Options=rw,nosuid,nodev,noexec,relatime,mode=700

   [Install]
   WantedBy=multi-user.target
   EOF

   systemctl daemon-reload
   systemctl start sys-fs-bpf.mount
   systemctl enable sys-fs-bpf.mount
   ```

#### Configure {{site.prodname}} to talk directly to the API server

In eBPF mode, {{site.prodname}} implements Kubernetes service networking directly (rather than relying on `kube-proxy`).  This means that, like `kube-proxy`,  {{site.prodname}} must connect _directly_ to the Kubernetes API server rather than via the API server's ClusterIP.

{% include content/kube-apiserver-host-port.md %}

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

Wait 60s for kubelet to pick up the `ConfigMap` (see Kubernetes [issue #30189](https://github.com/kubernetes/kubernetes/issues/30189){:target="_blank"}); then, restart the operator to pick up the change:

```
kubectl delete pod -n tigera-operator -l k8s-app=tigera-operator
```

The operator will then do a rolling update of {{site.prodname}} to pass on the change.  Confirm that pods restart and then reach the `Running` state with the following command:

```
watch kubectl get pods -n calico-system
```

If you do not see the pods restart then it's possible that the `ConfigMap` wasn't picked up (sometimes Kubernetes is slow to propagate `ConfigMap`s due the above issue).  You can try restarting the operator again.

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

In eBPF mode {{site.prodname}} replaces `kube-proxy` so running both would waste resources.  This section explains how
to disable `kube-proxy` in some common environments.

##### Clusters that run `kube-proxy` with a `DaemonSet` (such as `kubeadm`)

For a cluster that runs `kube-proxy` in a `DaemonSet` (such as a `kubeadm`-created cluster), you can disable `kube-proxy`, reversibly, by adding a node selector to `kube-proxy`'s `DaemonSet` that matches no nodes, for example:

```
kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
```

Then, should you want to start `kube-proxy` again, you can simply remove the node selector.

If you choose not to disable `kube-proxy` (for example, because it is managed by your Kubernetes distribution), then you *must* change Felix configuration parameter `BPFKubeProxyIptablesCleanupEnabled` to `false`.  This can be done with `calicoctl` as follows:

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfKubeProxyIptablesCleanupEnabled": false}}'
```

If both `kube-proxy` and `BPFKubeProxyIptablesCleanupEnabled` is enabled then `kube-proxy` will write its iptables rules and Felix will try to clean them up resulting in iptables flapping between the two.

##### OpenShift

If you are running OpenShift, you can disable `kube-proxy` as follows:

```
kubectl patch networks.operator.openshift.io cluster --type merge -p '{"spec":{"deployKubeProxy": false}}'
```

To re-enable it:

```
kubectl patch networks.operator.openshift.io cluster --type merge -p '{"spec":{"deployKubeProxy": true}}'
```

#### Configure data interface

If the name of the your node's interface doesn't match the default regular expression of `^(en.*|eth.*|tunl0$)`, you must configure felix to detect your interface by modifying the `bpfDataIfacePattern` configuration option with an appropriate regex.

```
calicoctl patch felixconfiguration default --patch='{"spec": {"bpfDataIfacePattern": "<Regular expression>"}}'
```

#### Enable eBPF mode

**The next step depends on whether you installed {{site.prodname}} using the operator, or a manifest:**

{% tabs tab-group:grp2 %}
<label:Operator,active:true>
<%

If you installed {{site.prodname}} using the operator, change the `spec.calicoNetwork.linuxDataplane` parameter in
the operator's `Installation` resource to `"BPF"`; you must also clear the `hostPorts` setting because host ports
are not supported in BPF mode:

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

Enabling eBPF mode should not disrupt existing connections but existing connections will continue to use the standard
Linux datapath. You may wish to restart pods to ensure that they start new connections using the BPF dataplane.

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

1. Monitor existing workloads to make sure they re-establish any connections disrupted by the switch.

### Send us feedback

The eBPF dataplane is still fairly new, and we want to hear about your experience.  Please don’t hesitate to connect with us via the {% include open-new-window.html text='Calico Users Slack' url='http://slack.projectcalico.org/' %} group.
