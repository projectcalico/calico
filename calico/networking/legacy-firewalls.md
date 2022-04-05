---
title: Restrict a pod to use an IP address in a specific range
description: Restrict the IP address chosen for a pod to a specific range of IP addresses.
---

### Big picture

Restrict the IP address chosen for a pod to a specific range of IP addresses.

### Value

When Kubernetes pods interact with external systems that make decisions based on IP ranges (for example legacy firewalls), it can be useful to define several IP ranges and explicitly assign pods to those ranges. Using {{site.prodname}} IP Address Management (IPAM), you can restrict a pod to use an address from within a specific range.

### Features

This how-to guide uses the following features: 

- **{{site.prodname}} IPAM**
- **IPPool resource**  

### Concepts

#### Kubernetes pod CIDR 

The **Kubernetes pod CIDR** is the range of IPs Kubernetes expects pod IPs to be assigned from.   It is defined for the entire cluster and is used by various Kubernetes components to determine whether an IP belongs to a pod. For example, kube-proxy treats traffic differently if that traffic is from a pod than if it is not. All pod IPs must be in the CIDR range for Kubernetes to function correctly.

#### IP Pool

**IP pools** are ranges of IP addresses from which {{site.prodname}} assigns pod IPs. By default, {{site.prodname}} creates an IP pool for the entire Kubernetes pod CIDR, but you can change this to break the pod CIDR up into several pools. You can control which pool {{site.prodname}} uses for each pod using node selectors, or annotations on the pod or the pod’s namespace.

### Before you begin...

The features in this How to guide require: 

- {{site.prodname}} IPAM

{% include content/determine-ipam.md %}

Additionally, cluster administrators must have [configured IP pools]({{ site.baseurl }}/reference/resources/ippool) to define the valid IP ranges to use for allocating pod IP addresses.

### How to

#### Restrict a pod to use an IP address range

Annotate the pod with key `cni.projectcalico.org/ipv4pools` and/or `cni.projectcalico.org/ipv6pools` and value set to a list of IP pool names, enclosed in brackets.  For example:

```
cni.projectcalico.org/ipv4pools: '["pool-1", "pool-2"]'
```

Note the use of the escaped \" for the inner double quotes around the pool names.

#### Restrict all pods within a namespace to use an IP address range

Annotate the namespace with key `cni.projectcalico.org/ipv4pools` and/or `cni.projectcalico.org/ipv6pools` and value set to a list of IP pool names, enclosed in brackets.  For example:

```
cni.projectcalico.org/ipv4pools: '["pool-1", "pool-2"]'

```

Note the use of the escaped `\"` for the inner double quotes around the pool names.

If both the pod and the pod’s namespace have the annotation, the pod annotation takes precedence.

The annotation must be present at the time the pod is created. Adding it to an existing pod has no effect. 

### Above and beyond

For help configuring {{site.prodname}} IPAM, see [Configuring the {{site.prodname}} CNI Plugins]({{ site.baseurl }}/reference/cni-plugin/configuration). 
