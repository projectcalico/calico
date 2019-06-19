---
title: Use ICMP/ping in policy rules
---

### Big picture

Use Calico network policy to allow and deny ICMP/ping messages. 

### Value

The **Internet Control Message Protocol (ICMP)** provides valuable network diagnostic functions, but it can also be used maliciously. Attackers can use it to learn about your network, or for DoS attacks. Using Calico network policy, you can control where ICMP is used. For example, you can:

- Allow ICMP ping, but only within your cluster 
- Allow ICMP for specifically labeled pods 
  For example, allow ICMP for pods launched by operators for diagnostic purposes, but block other uses.
- Temporarily enable ICMP to diagnose a problem, then disable it after the problem is resolved
- Deny/allow ICMP messages(ICMPv4 and/or ICMPv6)

### Features

This how-to guide uses the following Calico features:

**GlobalNetworkPolicy**or**NetworkPolicy** with ICMPv4 and ICMPv6 and positive/negative match criteria.


### Concepts

#### ICMP packet type and code

Calico network policy lets you deny and allow specific parts of the ICMP packet for fine-grain control. Calico network policy also lets you deny and allow specific parts of the ICMP packet for fine-grain control. For example, you can specify ICMP type 5, code 2. For details, see [ICMP type and code](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages).

### How to

- [Deny all ICMP](#deny-all-icmp)
- [Allow ICMP ping only within a cluster](#allow-icmp-ping-only-within-a-cluster)
- [Allow ICMP matching protocol type and code](#allow-icmp-matching-protocol-type-and-code)

#### Deny all ICMP

In this example, all pods are blocked from sending or receiving **ICMPv4** and **ICMPv6** messages. If**ICMPv6** messages are not used in your deployment, it is good practice to deny it specifically as shown below. 

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: block-icmp
spec:
  selector: all()
  types:
  - Ingress
  - Egress
  # Deny workloads from receiving any ICMP messages
  ingress:
  - action: Deny
    protocol: ICMP
  - action: Deny
    protocol: ICMPv6
  # Deny workloads from sending any ICMP messages
  egress:
  - action: Deny
    protocol: ICMP
  - action: Deny
    protocol: ICMPv6    
```

#### Allow ICMP ping only within a cluster

In this example, workloads can receive **ICMPv4 type 8**and**ICMPv6 type 128** ping requests only from inside the cluster. All other traffic is denied. 

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-ping-in-cluster
spec:
  selector: all()
  types:
  - Ingress
  # Only allow pods to receive ping from inside the cluster
  ingress:
  - action: Allow
    protocol: ICMP
    source:
      selector: all()
    icmp:
      type: 8 # Ping request
  - action: Allow
    protocol: ICMPv6
    source:
      selector: all()
    icmp:
      type: 128 # Ping request
  # Implicitly denies any other traffic 

```

#### Allow ICMP matching protocol type and code

In this example, workloads are allowed to receive ICMPv4 **code: 1 # host unreachable** messages, but no other ICMP messages.

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-host-unreachable
spec:
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: ICMP
    icmp:
      type: 3 # Destination unreachable
      code: 1 # Host unreachable
```

### Above and beyond

For more on the ICMP match criteria, see:

- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy) 
- [Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy)
