---
title: Use ICMP/ping rules in policy
description: Control where ICMP/ping is used by creating a Calico network policy to allow and deny ICMP/ping messages for workloads and host endpoints.
---

### Big picture

Use {{site.prodname}} network policy to allow and deny ICMP/ping messages.

### Value

The **Internet Control Message Protocol (ICMP)** provides valuable network diagnostic functions, but it can also be used maliciously. Attackers can use
it to learn about your network, or for DoS attacks. Using {{site.prodname}} network policy, you can control where ICMP is used. For example, you can:

- Allow ICMP ping, but only for workloads, host endpoints (or both)
- Allow ICMP for pods launched by operators for diagnostic purposes, but block other uses
- Temporarily enable ICMP to diagnose a problem, then disable it after the problem is resolved
- Deny/allow ICMPv4 and/or ICMPv6

### Features

This how-to guide uses the following {{site.prodname}} features:

**GlobalNetworkPolicy** or **NetworkPolicy** with:

- Protocol match for ICMPv4 and ICMPv6
- icmp/NotICMP match for ICMP type and code

### Concepts

#### ICMP packet type and code

{{site.prodname}} network policy also lets you deny and allow ICMP traffic based on specific types and codes. For example, you can specify ICMP type 5, code 2 to match specific ICMP redirect packets.

For details, see [ICMP type and code](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages){:target="_blank"}.

### How to

- [Deny all ICMP, all workloads and host endpoints](#deny-all-icmp-all-workloads-and-host-endpoints)
- [Allow ICMP ping, all workloads and host endpoints](#allow-icmp-ping-all-workloads-and-host-endpoints)
- [Allow ICMP matching protocol type and code, all Kubernetes pods](#allow-icmp-matching-protocol-type-and-code-all-Kubernetes-pods)

#### Deny all ICMP, all workloads and host endpoints

In this example, we introduce a "deny all ICMP" **GlobalNetworkPolicy**.

This policy **selects all workloads and host endpoints**. It enables a default deny for all workloads and host endpoints, in addition to the explicit ICMP deny rules specified in the policy.

If your ultimate goal is to allow some traffic, have your regular "allow" policies in place before applying a global deny-all ICMP traffic policy.

In this example, all workloads and host endpoints are blocked from sending or receiving **ICMPv4** and **ICMPv6** messages.

If **ICMPv6** messages are not used in your deployment, it is still good practice to deny them specifically as shown below.

In any "deny-all" {{site.prodname}} network policy, be sure to specify a lower order (**order:200**) than regular policies that might allow traffic.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: block-icmp
spec:
  order: 200
  selector: all()
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

#### Allow ICMP ping, all workloads and host endpoints

In this example, workloads and host endpoints can receive **ICMPv4 type 8** and **ICMPv6 type 128** ping requests that come from other workloads and host endpoints.

All other traffic may be allowed by other policies. If traffic is not explicitly allowed, it will be denied by default.

The policy applies only to **ingress** traffic. (Egress traffic is not affected, and default deny is not enforced for egress.)

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-ping-in-cluster
spec:
  selector: all()
  types:
  - Ingress
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
```

#### Allow ICMP matching protocol type and code, all Kubernetes pods

In this example, only Kubernetes pods that match the selector **projectcalico.org/orchestrator == 'kubernetes'** are allowed to receive ICMPv4 **code: 1 # host unreachable** messages.

```yaml
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

- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
- [Network policy]({{ site.baseurl }}/reference/resources/networkpolicy)
