---
title: Enable default deny for Kubernetes pods
---

### Big picture

Change the default for Kubernetes pods from allowing all traffic, to denying all traffic using Kubernetes or Calico network policy.  

### Value

A **default deny** network policy provides an enhanced security posture -- so workloads without policy (or incorrect policy) are not allowed traffic until appropriate network policy is defined.

### Features

This how-to guide uses the following Calico features:
- **NetworkPolicy** 
- **GlobalNetworkPolicy**

### Concepts

#### Default deny/allow behavior

**Default allow** means all traffic is allowed by default, unless otherwise specified. **Default deny** means all traffic is denied by default, unless explicitly allowed. **Kubernetes pods are default allow**, unless network policy is defined to specify otherwise.

For compatibility with Kubernetes, **Calico network policy** enforcement follows the standard convention for Kubernetes pods:
- If no network policies apply to a pod, then all traffic to/from that pod is allowed.
- If one or more network policies apply to a pod with type ingress, then only the ingress traffic specifically allowed by those policies is allowed, and all other traffic to/from the pod is denied.
- If one or more network policies apply to a pod with type egress, then only the egress traffic specifically allowed by those policies is allowed, and all other traffic to/from the pod is denied.

For other endpoint types (VMs, host interfaces), **Calico global network policy is default deny**. Only traffic specifically allowed by network policy is allowed, even if no network policies apply to the endpoint.

#### Best practice: implicit default deny policy

Whether you use a network policy or global network policy, we recommend that you create a "plain vanilla" default deny policy that does not include other deny rules. This best practice ensures that unwanted traffic is denied by default. Note that implicit default deny policy always occurs last; if any other policy allows the traffic, then the deny does not come into effect. The deny is executed only after all other policies are evaluated. 

### How to

**Best practice**

Although you can use any of the following policies to create default deny for Kubernetes pods, we recommend using the Calico global network policy. A Calico global network policy applies to both workloads (VMs and containers) and hosts (computers that run the hypervisor for VMs, or container runtime for containers). Using a Calico global network policy supports a conservative security stance for protecting resources. 

- [Create default deny traffic Calico global network policy, non-namespaced](#create-default-deny-traffic-calico-global-network-policy-non-namespaced)
- [Create default deny traffic Calico network policy, namespaced](#create-default-deny-traffic-calico-network-policy-namespaced)
- [Create default deny traffic Kubernetes policy, namespaced](#create-default-deny-traffic-Kubernetes-policy-namespaced)

#### Create default deny traffic Calico global network policy, non-namespaced

In the following example, we specify a default deny **GlobalNetworkPolicy** for ingress and egress traffic for all workloads and hosts by using the **selector: all()**. 

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: all()
  types:
  - Ingress
  - Egress
```

#### Create default deny traffic Calico network policy, namespaced  

In the following example, we specify a default deny **NetworkPolicy** that denies all traffic for workloads in the namespace, **engineering**. It is an implicit default deny policy without rules; it will always be in effect, regardless of the ordering scheme that you may specify in normal policies. 

```
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: engineering
spec:
  selector: all()
  types:
  - Ingress
  - Egress  
```

#### Create default deny traffic Kubernetes policy, namespaced

The following example is a Kubernetes default deny network policy. It prevents all traffic to/from all pods in the default namespace, and does not explicitly allow any traffic. 

Because the default changes when pods are selected by a network policy, the result is: **deny all ingress and egress traffic**. (Unless the traffic is allowed by another network policy).

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
spec:
  podSelector:
    matchLabels: {}
  types:
  - Ingress
  - Egress
```

### Above and beyond

- [Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy) 
- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy)
