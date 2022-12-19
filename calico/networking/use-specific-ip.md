---
title: Use a specific IP address with a pod
description: Specify the IP address for a pod instead of allowing Calico to automatically choose one.
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

Your cluster must be using Calico IPAM in order to use this feature.

{% include content/determine-ipam.md %}

### How to

Annotate the pod with cni.projectcalico.org/ipAddrs set to a list of IP addresses to assign, enclosed in brackets. For example:

<pre>
  "cni.projectcalico.org/ipAddrs": "[\"192.168.0.1\"]"
</pre>

Note the use of the escaped `\"` for the inner double quotes around the addresses.

The address must be within a configured Calico IP pool and not currently in use. The annotation must be present when the pod is created; adding it later has no effect.

Note that currently only a single IP address is supported per-pod using this annotation.

#### Reserving IPs for manual assignments

The `cni.projectcalico.org/ipAddrs` annotation requires the IP address to be within an IP pool.  This means that,
by default, {{site.prodname}} may decide to use the IP address that you select for another workload or for an internal
tunnel address.  To prevent this, there are several options:

* To reserve a whole IPPool for manual allocations, you can set its [node selector](../reference/resources/ippool) to `"!all()"`.  Since the `!all()`  
  cannot match any nodes, the IPPool will not be used for any automatic assignments.

* To reserve part of a pool, you can create an [`IPReservation` resource](../reference/resources/ipreservation). This allows for certain IPs to be reserved so
  that Calico IPAM will not use them automatically.  However, manual assignments (using the annotation) can still use 
  IPs that are "reserved".

* To prevent {{site.prodname}} from using IPs from a certain pool for internal IPIP and/or VXLAN tunnel addresses, you 
  can set the `allowedUses` field on the [IPPool](../reference/resources/ippool) to `["Workload"]`.

### Above and beyond

For help configuring Calico CNI and Calico IPAM, see [Configuring the Calico CNI Plugins]({{ site.baseurl }}/reference/cni-plugin/configuration).
