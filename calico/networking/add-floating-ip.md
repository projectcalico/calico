---
title: Add a floating IP to a pod
description: Configure one or more floating IPs to use as additional IP addresses for reaching a Kubernetes pod.
---

### Big picture

Configure one or more floating IPs that can be used as additional IP addresses for reaching a Kubernetes pod.

### Value

Like Kubernetes Services, a floating IP provides a stable IP address to reach some network service that might be backed by different pods at different times.  The primary advantage over Kubernetes services is that floating IPs work on all protocols: not just TCP, UDP, and SCTP.  Unlike Kubernetes services, a floating IP fronts a single pod at a time and cannot be used for load balancing.

### Features

This how-to guide uses the following {{site.prodname}} features: 

**{{site.prodname}} CNI configuration file** with floating_ips enabled

### Concepts

A **floating IP** is an additional IP address assigned to a workload endpoint. These IPs “float” in the sense that they can be moved around the cluster and front different workload endpoints at different times.  The workload itself is generally unaware of the floating IP; the host uses network address translation (NAT) on incoming traffic to change the floating IP to the workload’s real IP before delivering packets to the workload.

A Kubernetes Service assigns a **cluster IP** that allows other endpoints on the network (and may also assign a nodePort and/or an external load balancer IP) to access a set of pods, using network address translation. In many circumstances, a Kubernetes Service can handle similar use cases as a floating IP, and is generally recommended for Kubernetes users because it is a native Kubernetes concept.  One thing you cannot do with Kubernetes Services is use protocols other than UDP, TCP, and SCTP (use of such protocols is fairly rare).

### Before you begin...

The features in this How to require: 

- {{site.prodname}} CNI plugin

To verify, ssh to one of the Kubernetes nodes and look for at the CNI plugin configuration, usually located at `/etc/cni/net.d/`.  If you see the file, `10-calico.conflist`, you are using the {{site.prodname}} CNI plugin. 

### How to

- [Enable floating IPs](#enable-floating-ips)
- [Configure a pod to use a floating IP](#configure-a-pod-to-use-a-floating-ip)

#### Enable floating IPs

{% tabs %}
  <label:Operator,active:true>
<%

Floating IPs for Kubernetes pods are not currently supported for operator-managed Calico clusters.

%>
  <label:Manifest>
<%

By default, floating IPs are disabled. To enable floating IPs, follow these steps.

Modify the calico-config ConfigMap in the kube-system namespace. In the `cni_network_config` section, add the following stanza to the “calico” plugin config section.

```
    "feature_control": {
         "floating_ips": true
     }
```

For example, your `cni_network_config` will look similar to the following after the update.

```
 cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion": "0.3.0",
      "plugins": [
        {
          "type": "calico",
          "log_level": "info",
          "datastore_type": "kubernetes",
          "nodename": "__KUBERNETES_NODE_NAME__",
          "mtu": __CNI_MTU__,
          "ipam": {
              "type": "calico-ipam"
          },
          "policy": {
              "type": "k8s"
          },
          "kubernetes": {
              "kubeconfig": "__KUBECONFIG_FILEPATH__"
          },
          "feature_control": {
              "floating_ips": true
          }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }
```

%>
{% endtabs %}

#### Configure a pod to use a floating IP

{% tabs %}
  <label:Operator,active:true>
<%

Floating IPs for Kubernetes pods are not currently supported for operator-managed Calico clusters.

%>
  <label:Manifest>
<%

Annotate the pod with the key `cni.projectcalico.org/floatingIPs` and the value set to a list of IP addresses enclosed in square brackets.  For correct advertisement to the rest of the cluster, all floating IPs must be within the range of a configured [IP pool]({{ site.baseurl }}/reference/resources/ippool).

For example:

<pre>
"cni.projectcalico.org/floatingIPs": "[\"10.0.0.1\"]"
</pre>

Note the use of the escaped `\"` for the inner double quotes around the addresses.

%>
{% endtabs %}
