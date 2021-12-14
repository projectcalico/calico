---
title: Enable extreme high-connection workloads
description: Create a Calico network policy rule to bypass Linux conntrack for traffic to workloads that experience extremely large number of connections. 
---

### Big picture

Use a {{site.prodname}} network policy rule to bypass Linux conntrack for traffic to workloads that experience extremely large number of connections.

### Value

When the number of connections on a node exceeds the number of connections that Linux conntrack can track, connections can be rejected or dropped. {{site.prodname}} network policy can be used to selectively bypass Linux conntrack for traffic to/from these types of workloads.

### Features

This how-to guide uses the following {{site.prodname}} features:
- A HostEndpoint
- A GlobalNetworkPolicy with a **doNotTrack** rule

### Concepts

#### Linux conntrack

Connection tracking (“conntrack”) is a core feature of the Linux kernel’s networking stack. It allows the kernel to keep track of all logical network connections or flows, and thereby identify all of the packets that make up each flow so they can be handled consistently together. Conntrack is an essential part of the mainline Linux network processing pipeline, normally improving performance, and enabling NAT and stateful access control.

#### Extreme high-connection workloads

Some niche workloads handling extremely high number of simultaneous connections, or very high rate of short lived connections, can exceed the maximum number of connections Linux conntrack is able to track. One real world example of such a workload is an extreme scale memcached server handling 50k+ connections per second.

#### {{site.prodname}} doNotTrack network policy

The {{site.prodname}} global network policy option, **doNotTrack**, indicates to apply the rules in the policy before connection tracking, and that packets allowed by these rules should not be tracked. The policy is applied early in the Linux packet processing pipeline, before any regular network policy rules, and independent of the policy order field. 

Unlike normal network policy rules, doNotTrack network policy rules are stateless, meaning you must explicitly specify rules to allow return traffic that would normally be automatically allowed by conntrack. For example, for a server on port 999, the policy must include an ingress rule allowing inbound traffic to port 999, and an egress rule to allow outbound traffic from port 999. 

In a doNotTrack policy:
- Ingress rules apply to all incoming traffic through a host endpoint, regardless of where the traffic is going 
- Egress rules apply only to traffic that is sent from the host endpoint (not a local workload)

Finally, you must add an **applyOnForward: true expression** for a **doNotTrack policy** to work.

### Before you begin...

Before creating a **doNotTrack** network policy, read this [blog](https://www.tigera.io/blog/when-linux-conntrack-is-no-longer-your-friend/){:target="_blank"} to understand use cases, benefits, and trade offs. 

### How to

#### Bypass connection traffic for high connection server

In the following example, a memcached server pod with **hostNetwork: true** was scheduled on the node memcached-node-1. We create a HostEndpoint for the node. Next, we create a GlobalNetwork Policy with symmetrical rules for ingress and egress with doNotTrack and applyOnForward set to true.

```yaml
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: memcached-node-1-eth0
  labels:
    memcached: server
spec:
  interfaceName: eth0  
  node: memcached-node-1  
  expectedIPs:
    - 10.128.0.162  
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: memcached-server
spec:
  selector: memcached == 'server'
  applyOnForward: true
  doNotTrack: true
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: memcached == 'client'
      destination:
        ports:
          - 12211
  egress:
    - action: Allow
      protocol: TCP
      source:
        ports:
          - 12211
      destination:
        selector: memcached == 'client'
```
### Above and beyond

[Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
