---
title: Enable default deny for Kubernetes pods
---

### Big picture

Change the default for Kubernetes pods from allowing all traffic, to denying all traffic using Kubernetes or Calico network policy.  

### Value

A **default deny** network policy provides an enhanced security posture -- so workloads without policy (or incorrect policy) do not allow traffic until appropriate network policy is defined.

### Features

This how-to guide uses the following Calico features:
- **NetworkPolicy** 
- **GlobalNetworkPolicy**

### Concepts

#### Default deny/allow behavior

Default allow means all traffic is allowed by default, unless otherwise specified. Default deny means all traffic is denied by default, unless explicitly allowed. **Kubernetes pods are default allow, unless network policy is defined to specify otherwise**.

For compatibility with Kubernetes, **Calico network policy** enforcement follows the standard convention for Kubernetes pods:
- If no network policies apply to a pod, then all traffic to/from that pod is allowed.
- If one or more network policies apply to a pod containing ingress rules, then only the ingress traffic specifically allowed by those policies is allowed, and all other traffic to/from the pod is denied.
- If one or more network policies apply to a pod containing egress rules, then only the egress traffic specifically allowed by those policies is allowed, and all other traffic to/from the pod is denied.

For other endpoint types (VMs, host interfaces), **Calico global network policy is default deny**. Only traffic specifically allowed by network policy is allowed, even if no network policies apply to the endpoint.

#### Secure resources everywhere

We recommend creating default deny using **Calico global network policy**, which is non-namespaced. It applies to both workloads (VMs and containers) and hosts (computers that run the hypervisor for VMs, or container runtime for containers). This supports a conservative security stance towards protecting resources.

#### Calico network policy: order matters

When you create Calico network policies to allow traffic, you can assign an **order** number that indicates the order you want policy applied relative to other policies. To ensure that your Calico default deny policy remains in effect at all times, assign a significantly higher number than regular policies that allow traffic.

### How to

Although you can use any of the following policies to create default deny for Kubernetes pods, we recommend using the Calico policy, non-namespaced.

- [Create default deny-all traffic Calico policy, non-namespaced](#create-default-deny-all-traffic-calico-policy-non-namespaced)
- [Create default deny-all traffic Calico policy, namespaced](#create-default-deny-all-traffic-calico-policy-namespaced)
- [Create default deny all traffic Kubernetes policy, namespaced](#create-default-deny-all-traffic-Kubernetes-policy-namespaced)

#### Create default deny-all traffic Calico policy, non-namespaced

In the following example, we specify a default deny global network policy that applies to workload endpoint resources in all namespaces, and host endpoint resources. The absence of rules means that no traffice is allowed by the policy. 

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

#### Create default deny-all traffic Calico policy, namespaced  

In the following example, we specify a default deny Calico network policy for workloads in the namespace, **engineering**. Because Calico network policy is namespaced, the **order:20** is higher relative to policies in this namespace to ensure it remains in effect at all times. Note that the **selector: all()** is not required, but is used for clarity. 

```
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: engineering
spec:
  order: 20
  selector: all()
  types:
  - Ingress
  - Egress  
```

#### Create default deny-all traffic Kubernetes policy, namespaced

The following example is a Kubernetes default deny-all ingress and egress network policy. It prevents all traffic to/from all pods in the **policy-demo** namespace, and does not explicitly allow any traffic. 

Because the default changes when pods are selected by a network policy, the result is: **deny all ingress and egress traffic**. (Unless the traffic is allowed by another network policy).

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
  namespace: policy-demo
spec:
  podSelector:
    matchLabels: {}
  types:
  - Ingress
  - Egress
```

### Above and beyond

- [Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy) 
- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy)
