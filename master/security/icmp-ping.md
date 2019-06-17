---
title: Use ICMP ping in policy rules
---

### Big picture

Allow and deny ICMP/ping in Calico network policy. 

### Value

The **Internet Control Message Protocol (ICMP)** provides valuable network diagnostic functions, but it can also be used maliciously. Attackers can use it to learn about your network, or for a DoS attack. Using Calico network policy, you can control when and where ICMP is used. For example, you can:

- Block ICMP entirely.
- Allow ICMP ping, but only within your cluster. 
- Allow ICMP for specifically labeled pods.  
  For example, allow ICMP for pods launched by operators for diagnostic purposes, but block other uses.
- Temporarily enable ICMP to diagnose a problem, then disable it after the problem is resolved.

### Features

This how-to guide uses the following Calico features:

**NetworkPolicy** with ICMP rules and positive/negative match criteria


### Concepts

#### ICMP packet type and code

Calico network policy lets you deny and allow specific parts of the ICMP packet for fine-grain control. For details, see [ICMP type and code](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)


### How to

- [Deny all ICMP ping](#deny-all-icmp-ping)
- [Allow ICMP ping only within a cluster, deny outside the cluster](#allow-icmp-ping-only-within-a-cluster-deny-outside-the-cluster)
- [Allow ICMP ping, matching protocol type and code](#allow-icmp-ping-matching-protocol-type-and-code)

#### Deny all ICMP ping

In this example, we assume 

```
```

#### Allow ICMP ping only within a cluster, deny outside the cluster 

In this example, we assume 

```
```

#### Allow ICMP ping, matching protocol type and code

In this example, we assume 
```
```

### Above and beyond

- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy) 
- [Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy)
