---
title: Enable default deny for Kubernetes pods
description: Create a default deny network policy so pods that are missing policy are not allowed traffic until appropriate network policy is defined.
---

### Big picture

Enable a default deny policy for Kubernetes pods using Kubernetes or {{site.prodname}} network policy.

### Value

A **default deny** network policy provides an enhanced security posture -- so pods without policy (or incorrect policy) are not allowed traffic until appropriate network policy is defined.

### Features

This how-to guide uses the following {{site.prodname}} features:
- **NetworkPolicy**
- **GlobalNetworkPolicy**

### Concepts

#### Default deny/allow behavior

**Default allow** means all traffic is allowed by default, unless otherwise specified. **Default deny** means all traffic is denied by default, unless explicitly allowed. **Kubernetes pods are default allow**, unless network policy is defined to specify otherwise.

For compatibility with Kubernetes, **{{site.prodname}} network policy** enforcement follows the standard convention for Kubernetes pods:
- If no network policies apply to a pod, then all traffic to/from that pod is allowed.
- If one or more network policies apply to a pod with type ingress, then only the ingress traffic specifically allowed by those policies is allowed.
- If one or more network policies apply to a pod with type egress, then only the egress traffic specifically allowed by those policies is allowed.

For other endpoint types (VMs, host interfaces), the default behavior is to deny traffic. Only traffic specifically allowed by network policy is allowed, even if no network policies apply to the endpoint.

#### Best practice: implicit default deny policy

We recommend creating an implicit default deny policy for your Kubernetes pods, regardless if you use {{site.prodname}} or Kubernetes network policy. This ensures that unwanted traffic is denied by default. Note that implicit default deny policy always occurs last; if any other policy allows the traffic, then the deny does not come into effect. The deny is executed only after all other policies are evaluated.

### How to

Although you can use any of the following policies to create default deny policy for Kubernetes pods, we recommend using the {{site.prodname}} global network policy. A {{site.prodname}} global network policy applies to all workloads (VMs and containers) in all namespaces, as well as hosts (computers that run the hypervisor for VMs, or container runtime for containers). Using a {{site.prodname}} global network policy supports a conservative security stance for protecting resources.

- [Enable default deny {{site.prodname}} global network policy, non-namespaced](#enable-default-deny-calico-global-network-policy-non-namespaced)
- [Enable default deny {{site.prodname}} network policy, namespaced](#enable-default-deny-calico-network-policy-namespaced)
- [Enable default deny Kubernetes policy, namespaced](#enable-default-deny-Kubernetes-policy-namespaced)

#### Enable default deny {{site.prodname}} global network policy, non-namespaced

In the following example, we enable a default deny **GlobalNetworkPolicy** for all workloads and hosts.

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

#### Enable default deny {{site.prodname}} network policy, namespaced

In the following example, we enable a default deny **NetworkPolicy** for all workloads in the namespace, **engineering**.

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

#### Enable default deny Kubernetes policy, namespaced

In the following example, we enable a default deny **Kubernetes network policy** for all pods in the namespace, **engineering**.

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: engineering
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Above and beyond

- [Network policy]({{ site.baseurl }}/reference/resources/networkpolicy)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
