---
title: Use ICMP/ping in policy rules
---

### Big picture

Use Calico network policy to allow and deny ICMP/ping messages. 

### Value

The **Internet Control Message Protocol (ICMP)** provides valuable network diagnostic functions, but it can also be used maliciously. Attackers can use it to learn about your network, or for DoS attacks. Using Calico network policy, you can control where ICMP is used. For example, you can:

- Allow ICMP ping, but only within your cluster 
- Allow ICMP for pods launched by operators for diagnostic purposes, but block other uses
- Temporarily enable ICMP to diagnose a problem, then disable it after the problem is resolved
- Deny/allow ICMPv4 and/or ICMPv6

### Features

This how-to guide uses the following Calico features:

**GlobalNetworkPolicy** or **NetworkPolicy** with:

- Protocol match for ICMPv4 and ICMPv6
- icmp/NotICMP match for ICMP type and code

### Concepts

#### ICMP packet type and code

Calico network policy also lets you deny and allow ICMP traffic based on specific types and codes. For example, you can specify ICMP type 5, code 2 to match specific ICMP redirect packets. 

For details, see [ICMP type and code](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages).

### How to

- [Deny all ICMP](#deny-all-icmp)
- [Allow ICMP ping only within a cluster](#allow-icmp-ping-only-within-a-cluster)
- [Allow ICMP matching protocol type and code, only within a cluster](#allow-icmp-matching-protocol-type-and-code-only-within-a-cluster)

#### Deny all ICMP

In this example, we introduce a "deny all ICMP" **GlobalNetworkPolicy**. 

This policy **selects all workloads in the cluster**. It enables a default deny for all workloads, in addition to the explicit ICMP deny rules specified in the policy. For more on default deny policy, see [Calico Network Policy]({{site.baseurl}}/{{page.version}}/security/caliconetworkpolicy).   

If your ultimate goal is to allow some traffic, have your regular "allow" policies in place before applying the global deny-all policy.

In this example, all workloads are blocked from sending or receiving **ICMPv4** and **ICMPv6** messages. Because a GlobalNetworkPolicy applies to hostendpoints as well, to limit the policy to only workloads, we use the selector **projectcalico.org/orchestrator == 'kubernetes'**.

If **ICMPv6** messages are not used in your deployment, it is still good practice to deny them specifically as shown below. 

In any "deny-all" Calico network policy, be sure to specify a lower order (**order:200**) than regular policies that might allow traffic.   

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: block-icmp
spec:
  order: 200
  selector: projectcalico.org/orchestrator == 'kubernetes'
  types:
  - Ingress
  - Egress
  ingress:
  - action: Deny
    protocol: ICMP
  - action: Deny
    protocol: ICMPv6
  egress:
  - action: Deny
    protocol: ICMP
  - action: Deny
    protocol: ICMPv6    
```

#### Allow ICMP ping only within a cluster

In this example, workloads can receive **ICMPv4 type 8** and **ICMPv6 type 128** ping requests only from inside the cluster.

All other traffic may be allowed by other policies. If traffic is not explicitly allowed, it will be denied by default. The policy applies only to **ingress** traffic; egress traffic is not affected, and default deny is not enforced. 

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-ping-in-cluster
spec:
  selector: projectcalico.org/orchestrator == 'kubernetes'
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: ICMP
    source:
      selector: projectcalico.org/orchestrator == 'kubernetes'
    icmp:
      type: 8 # Ping request
  - action: Allow
    protocol: ICMPv6
    source:
      selector: projectcalico.org/orchestrator == 'kubernetes'
    icmp:
      type: 128 # Ping request
```

#### Allow ICMP matching protocol type and code

In this example, only workloads are allowed (by using selector **projectcalico.org/orchestrator == 'kubernetes'**) to receive ICMPv4 **code: 1 # host unreachable** messages, but no other ICMP messages.

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-host-unreachable
spec:
  selector: projectcalico.org/orchestrator == 'kubernetes'
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
