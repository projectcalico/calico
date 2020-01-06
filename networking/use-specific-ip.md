---
title: Use a specific IP address with a pod
Description: Specify the IP address for a pod instead of allowing Calico to choose automatically.
---

### Big picture

Choose the IP address for a pod instead of allowing Calico to choose automatically.

### Value

Some applications require the use of stable IP addresses. Also, you may want to create entries in external DNS servers that point directly to pods, and this requires static IPs.

### Features

This how-to guide uses the following features: 

- **Calico IPAM**
- **IPPool** resource


### Concepts

#### Kubernetes pod CIDR

The **Kubernetes pod CIDR** is the range of IPs Kubernetes expects pod IPs to be assigned from.  It is defined for the entire cluster and is used by various Kubernetes components to determine whether an IP belongs to a pod. For example, kube-proxy treats traffic differently if an IP is from a pod than if it is not. All pod IPs must be in the CIDR range for Kubernetes to function correctly.

**IP Pools**

IP pools are ranges of IP addresses from which Calico assigns pod IPs. Static IPs must be in an IP pool.

### Before you begin...

You must be using the Calico IPAM.

If you are not sure, ssh to one of your Kubernetes nodes and examine the CNI configuration.

<pre>
cat /etc/cni/net.d/10-calico.conflist
</pre>

Look for the entry:

<pre>
         "ipam": {
              "type": "calico-ipam"
          },
</pre>

If it is present, you are using the Calico IPAM. If the IPAM is set to something else, or the 10-calico.conflist file does not exist, you cannot use these features in your cluster.

### How to

Annotate the pod with cni.projectcalico.org/ipAddrs set to a list of IP addresses to assign, enclosed in brackets. For example:

<pre>
  "cni.projectcalico.org/ipAddrs": "[\"192.168.0.1\"]"
</pre>

Note the use of the escaped `\"` for the inner double quotes around the addresses.

The address must be within a configured Calico IP pool and not currently in use. The annotation must be present when the pod is created; adding it later has no effect.

Note that currently only a single IP address is supported per-pod using this annotation.

### Above and beyond

For help configuring Calico CNI and Calico IPAM, see [Configuring the Calico CNI Plugins]({{ site.baseurl }}/reference/cni-plugin/configuration).
