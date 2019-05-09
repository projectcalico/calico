---
title: Enable extreme high-connection workloads 
---

### Big Picture

Use a Calico network policy rule to bypass specific Linux conntrack traffic to improve workload performance.

### Value

Using a single Calico network policy rule, you can easily fine-tune the Linux conntrack to improve workload performance. 

A typical use case is a workload that uses a memcached server to speed up page load times and handle spikes in demand. If the server handles more than 50,000+ short-lived connections, its conntrack table can fill up and connections can be rejected or dropped. If you have already tried tweaking the conntrack table size and timeouts, using a Calico network policy may help.

### Features

This how-to guide uses the following Calico features:
- A Calico host endpoint
- A Calico global network policy with a **doNotTrack** rule

### Concepts

#### Connection tracking starts early in packet processing

The Calico network policy rule, **doNotTrack**, turns off connection tracking for specific traffic. The rule is applied early in the Linux packet processing pipeline, before any regular network policy rules, and is independent of policy order. The benefit of turning off connection tracking to increase performance, can also be used to stop connection flooding on a host during a DoS attack.

#### Create ingress and egress rules for doNotTrack policies

Linux conntrack improves performance because only the first packet in a flow goes through the full network stack processing. In a normal Calico network policy, you specify only the ingress rule, and connection tracking automatically allows the egress path. 

However, when you disable connection tracking using **doNotTrack** in a policy, conntrack no longer knows what to do with egress traffic. You must explicitly specify the egress traffic to be allowed. For example, for a server on port 999, the policy must include an ingress rule allowing inbound traffic **to** port 999, and an egress rule to allow outbound traffic **from** port 999. If you do not create an egress traffic rule in a doNotTrack policy, the server will stop responding because it does not know what to do. 

In a doNotTrack policy:
- Ingress rules apply to all incoming traffic through a host endpoint—regardless of where the traffic is going. 
- Egress rules apply only to traffic that is sent from the host endpoint (not a local workload)

Finally, you must add an **applyOnForward: true** expression for a **DoNotTrack** policy to work.

### Before you begin...

Before creating a DoNotTrack network policy, read this [blog](https://www.tigera.io/blog/when-linux-conntrack-is-no-longer-your-friend/) to understand use cases, benefits, and trade offs. 

### How to

#### Bypass connection traffic for high connection server

In the following example, on the node jasper-node-0, we create a host endpoint for a high-traffic memcached server. Next, we create a global network policy with symmetrical rules for ingress and egress with DoNotTrack and ApplyOnForward set to true.

```
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: high-traffic-memcached
  labels:
    node: memcached
spec:
  interfaceName: eng4  
  node: jasper-node-0  
  expectedIPs:
    - 10.128.0.162  
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-tcp-12211
spec:
  selector: node == 'memcached'
  applyOnForward: true
  doNotTrack: true
  ingress:
    - action: Allow
      protocol: TCP
      #source:
        #selector: run == 'frontend'
      destination:
        ports:
          - 12211
  egress:
    - action: Allow
      protocol: TCP
      source:
        ports:
          - 12211
      #destination:
        #selector: run == 'frontend'
```

### Above and 

- [Calico Global Network Policy API](https://docs.projectcalico.org/v3.6/reference/calicoctl/resources/globalnetworkpolicy)
- [Blog: When Linux is no longer your friend](https://www.tigera.io/blog/when-linux-conntrack-is-no-longer-your-friend/)

