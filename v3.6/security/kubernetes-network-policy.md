---
title: Kubernetes network policy
---

### Big picture

Kubernetes network policy lets administrators and developers enforce network connections using rules. 

### Value

Kubernetes network policy lets developers secure access to and from their applications using the same simple language they use to deploy them. Developers can focus on their applications without understanding low-level networking concepts. Enabling developers to easily secure their applications using network policies, supports a shift left DevOps environment. 

### Features

The Kubernetes Network Policy API supports: 

**Network policies** that are:
- Namespace scoped
- Applied to pods using label selectors

**Network policy rules** that specify:
- Ingress/egress connections that are allowed to/from pods, namespaces, or CIDRs
- Protocols (STCP)
- Named ports or port numbers

### Concepts

Calico supports the complete Kubernetes Network Policy API, and extends it with additional policy features. For details, see Calico Network Policy.

The Kubernetes Network Policy API lets you specify rules for controlling network connections. It provides L3/L4 IP address and port-based network segmentation. However, to enforce the network policy rules, you need a network plugin like Calico.

#### Ingress and egress

The bulk of securing network connections typically revolves around defining egress and ingress rules. Ingress is an incoming connection to a Kubernetes pod. Egress is an outgoing connection from a Kubernetes pod. In network policy you create ingress and egress “allow” rules, which you can apply independently (egress, ingress, or both). 

#### Default deny/allow 

**Default allow** means all connections are allowed by default, unless otherwise specified. 
**Default deny** means all connections are denied by default, unless explicitly allowed. 

### How to

Before you create your first network policy, you need to understand the default network policy behaviors. 
- If you do not create any Kubernetes network policies, then all pods are allowed to communicate with all other pods. 
- When you create one or more network policies, any connections that are not explicitly allowed by the policy are treated as **default-deny** when pods are selected. 

You are now ready to start fine-tuning what connections should be allowed. This section describes how to create policies for the following tasks:

- [Create ingress policies](#create-ingress-policies)
- [Allow ingress connections, pods in same namespace](#allow-ingress-connections-pods-in-same-namespace)
- [Allow ingress connections, pods in different namespace](#allow-ingress-connections-pods-in-different-namespace)
- [Create egress policies](#create-egress-policies)
- [Allow ingress connections, pods in same namespace](#allow-egress-connections-pods-in-same-namespace)
- [Allow ingress connections, pods with IP address or CIDR range](#allow-egress-connections-pods-with-ip-address-or-cidr-range)
- [Best practice: create deny-all default network policies](#best-practice-create-deny-all-default-network-policies)
- [Create deny-all default ingress and egress policy, pods in same namespace](#create-deny-all-default-ingress-and-egress-policy-pods-in-same-namespace)

#### Create ingress policies

Create ingress network policies to allow inbound connections from other pods. 

Network policies apply to pods within a specific namespace. Policies can include one or more ingress rules. To specify which pods in the namespace the network policy applies to, use a **pod selector**; use a **ports:** field to define which ports should be allowed. 

##### Allow ingress connections, pods in same namespace

In the following example, incoming connections to pods with label **color=blue** are allowed only if they come from a pod with **color=red**, on port **80**.

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-same-namespace
  namespace: default
spec:
  podSelector:
    matchLabels: {“color”: “blue”}
  ingress:
  - from:
    - podSelector: {“color”: “red”}
    to:
      ports:
      - port: 80
```
{: .no-select-button}

##### Allow ingress connections, pods in different namespace

To allow connections from pods in a different namespace, use a **namespace selector**. In the following policy, the namespace selector matches one or more Kubernetes namespaces and is combined with the pod selector. 

>**Note**: Namespace selectors can only be used in policy rules. The **spec.podSelector** applies only to pods in the same namespace as the policy.
{: .alert .alert-info}

In the following example, incoming connections to pods are allowed only if they come from a pod with **color=red**, in a namespace with **something=else**, on port **80**.

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-same-namespace
  namespace: default
spec:
  podSelector:
    matchLabels: {“color”: “blue”}
  ingress:
  - from:
    - podSelector: {“color”: “red”}
      namespaceSelector: {“something”: “else”}
    to:
      ports:
      - port: 80
```  
{: .no-select-button}

#### Create egress policies

Create egress network policies to allow outbound connections from pods. 

##### Allow egress connections, pods in same namespace

The following policy allows pod outbound connections to other pods in the same namespace that match the pod selector. In the following example, outbound connections are allowed only if they are going to a pod with **color=red**, on port **80**.

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-egress-same-namespace
  namespace: default
spec:
  podSelector:
    matchLabels: {“color”: “blue”}
  egress:
  - to:
    - podSelector: {“color**”: “red”}
      ports:
      - port: 80
```      
{: .no-select-button}

##### Allow egress connections, pods with IP address or CIDR range

Egress policies can also be used to allow connections to specific IP addresses and CIDR ranges. Typically, IP addresses/ranges are used to handle connections external to the cluster for static resources or subnets. 

The following policy allows connections to pods in CIDR, **172.18.0.0/24**.

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-egress-external
  namespace: default
spec:
  podSelector:
    matchLabels: {“color”: “red”}
  egress:
  - to:
    - ipBlock:
        cidr: 172.18.0.0/24
```        
{: .no-select-button}

#### Best practice: create deny-all default network policies

To ensure that all pods in the namespace are secure, a best practice is to create a default network policy. This avoids accidentally exposing an app or version that doesn’t have policy defined. 

##### Create deny-all default ingress and egress policy, pods in same namespace

The following network policy implements a default, **deny-all** ingress and egress policy that prevents all connections to pods in the **policy-demo** namespace. Note that the policy applies to all pods in the policy-demo namespace, but does not explicitly allow any connections. All pods are selected, but because the default changes when pods are selected by a network policy, the result is: **deny all ingress and egress connections**. (Unless the connection is allowed by another network policy).

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-ingress-deny
  namespace: policy-demo
spec:
  podSelector:
    matchLabels: {}
  types:
  - Ingress
Egress
```
{: .no-select-button}

### Above and Beyond

[Kubernetes Network Policy API documentation](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#networkpolicy-v1-networking-k8s-io)


