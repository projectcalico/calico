---
title: Get started with Kubernetes network policy
description: Learn Kubernetes policy syntax, rules, and features for controlling network traffic.
---

### Big picture

Kubernetes network policy lets administrators and developers enforce which network traffic is allowed using rules.

### Value

Kubernetes network policy lets developers secure access to and from their applications using the same simple language they use to deploy them. Developers can focus on their applications without understanding low-level networking concepts. Enabling developers to easily secure their applications using network policies supports a shift left DevOps environment.

### Features

The **Kubernetes Network Policy API** supports the following features:

- Policies are namespace scoped
- Policies are applied to pods using label selectors
- Policy rules can specify the traffic that is allowed to/from pods, namespaces, or CIDRs
- Policy rules can specify protocols (TCP, UDP, SCTP), named ports or port numbers

### Concepts

The Kubernetes Network Policy API provides a standard way for users to define network policy for controlling network traffic. However, Kubernetes has no built-in capability to enforce the network policy. To enforce network policy, you must use a network plugin such as Calico.

#### Ingress and egress

The bulk of securing network traffic typically revolves around defining egress and ingress rules. From the point of view of a Kubernetes pod, **ingress** is incoming traffic to the pod, and **egress** is outgoing traffic from the pod. In Kubernetes network policy, you create ingress and egress “allow” rules independently (egress, ingress, or both).

#### Default deny/allow behavior

**Default allow** means all traffic is allowed by default, unless otherwise specified.
**Default deny** means all traffic is denied by default, unless explicitly allowed.

### How to

Before you create your first Kubernetes network policy, you need to understand the default network policy behaviors. If no Kubernetes network policies apply to a pod, then all traffic to/from the pod are allowed (default-allow). As a result, if you do not create any network policies, then all pods are allowed to communicate freely with all other pods. If one or more Kubernetes network policies apply to a pod, then only the traffic specifically defined in that network policy are allowed (default-deny).

You are now ready to start fine-tuning traffic that should be allowed.

- [Create ingress policies](#create-ingress-policies)
- [Allow ingress traffic from pods in the same namespace](#allow-ingress-traffic-from-pods-in-the-same-namespace)
- [Allow ingress traffic from pods in a different namespace](#allow-ingress-traffic-from-pods-in-a-different-namespace)
- [Create egress policies](#create-egress-policies)
- [Allow egress traffic from pods in the same namespace](#allow-egress-traffic-from-pods-in-the-same-namespace)
- [Allow egress traffic to IP addresses or CIDR range](#allow-egress-traffic-to-ip-addresses-or-cidr-range)
- [Best practice: create deny-all default network policy](#best-practice-create-deny-all-default-network-policy)
- [Create deny-all default ingress and egress network policy](#create-deny-all-default-ingress-and-egress-network-policy)

#### Create ingress policies

Create ingress network policies to allow inbound traffic from other pods.

Network policies apply to pods within a specific **namespace**. Policies can include one or more ingress rules. To specify which pods in the namespace the network policy applies to, use a **pod selector**. Within the ingress rule, use another pod selector to define which pods allow incoming traffic, and the **ports** field to define on which ports traffic is allowed.

##### Allow ingress traffic from pods in the same namespace

In the following example, incoming traffic to pods with label **color=blue** are allowed only if they come from a pod with **color=red**, on port **80**.

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-same-namespace
  namespace: default
spec:
  podSelector:
    matchLabels:
      color: blue
  ingress:
  - from:
    - podSelector:
        matchLabels:
          color: red
    ports:
      - port: 80
```

##### Allow ingress traffic from pods in a different namespace

To allow traffic from pods in a different namespace, use a namespace selector in the ingress policy rule. In the following policy, the namespace selector matches one or more Kubernetes namespaces and is combined with the pod selector that selects pods within those namespaces.

>**Note**: Namespace selectors can be used only in policy rules. The **spec.podSelector** applies to pods only in the same namespace as the policy.
{: .alert .alert-info}

In the following example, incoming traffic is allowed only if they come from a pod with label **color=red**, in a namespace with label **shape=square**, on port **80**.

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-same-namespace
  namespace: default
spec:
  podSelector:
    matchLabels:
      color: blue
  ingress:
  - from:
    - podSelector:
        matchLabels:
          color: red
      namespaceSelector:
        matchLabels:
          shape: square
    ports:
    - port: 80
```

#### Create egress policies

Create egress network policies to allow outbound traffic from pods.

##### Allow egress traffic from pods in the same namespace

The following policy allows pod outbound traffic to other pods in the same namespace that match the pod selector. In the following example, outbound traffic is allowed only if they go to a pod with label **color=red**, on port **80**.

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-egress-same-namespace
  namespace: default
spec:
  podSelector:
    matchLabels:
      color: blue
  egress:
  - to:
    - podSelector:
        matchLabels:
          color: red
    ports:
    - port: 80
```

##### Allow egress traffic to IP addresses or CIDR range

Egress policies can also be used to allow traffic to specific IP addresses and CIDR ranges. Typically, IP addresses/ranges are used to handle traffic that is external to the cluster for static resources or subnets.

The following policy allows egress traffic to pods in CIDR, **172.18.0.0/24**.

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-egress-external
  namespace: default
spec:
  podSelector:
    matchLabels:
      color: red
  egress:
  - to:
    - ipBlock:
        cidr: 172.18.0.0/24
```

#### Best practice: create deny-all default network policy

To ensure that all pods in the namespace are secure, a best practice is to create a default network policy. This avoids accidentally exposing an app or version that doesn’t have policy defined.

##### Create deny-all default ingress and egress network policy

The following network policy implements a default **deny-all** ingress and egress policy, which prevents all traffic to/from pods in the **policy-demo** namespace. Note that the policy applies to all pods in the policy-demo namespace, but does not explicitly allow any traffic. All pods are selected, but because the default changes when pods are selected by a network policy, the result is: **deny all ingress and egress traffic**. (Unless the traffic is allowed by another network policy).

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
  namespace: policy-demo
spec:
  podSelector:
    matchLabels: {}
  policyTypes:
  - Ingress
  - Egress
```

### Above and beyond

- [Kubernetes Network Policy API documentation](https://kubernetes.io/docs/reference/kubernetes-api/policy-resources/network-policy-v1/){:target="_blank"}