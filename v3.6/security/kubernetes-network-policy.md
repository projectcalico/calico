---
title: Kubernetes network policy
---

### Big picture

Kubernetes network policy lets administrators and developers enforce network connections using rules. 

### Value

Kubernetes network policy lets developers secure access to and from their applications using the same simple language they use to deploy them. Developers can focus on their applications without understanding low-level networking concepts. Enabling developers to easily secure their applications using network policies supports a shift left DevOps environment. 

### Features

The Kubernetes Network Policy API supports the following features: 

- Policies are namespace scoped
- Policies are applied to pods using label selectors
- Policy rules can specify the connections that are allowed to/from pods, namespaces, or CIDRs
- Policy rules can specify protocols (TCP, UDP, SCTP), named ports or port numbers

### Concepts

The Kubernetes Network Policy API provides a standard way for users to define network policy for controlling network connections. However, Kubernetes has no built-in capability to enforce the network policy. To enforce network policy, you must use a network plugin such as Calico. 

#### Ingress and egress

The bulk of securing network connections typically revolves around defining egress and ingress rules. From the point of view of a Kubernetes pod, **ingress** is incoming connections to the pod, and **egress** is outgoing connections from the pod. In Kubernetes network policy, you create ingress and egress “allow” rules independently (egress, ingress, or both). 

#### Default deny/allow behavior

**Default allow** means all connections are allowed by default, unless otherwise specified. 
**Default deny** means all connections are denied by default, unless explicitly allowed. 

### How to

Before you create your first network policy, you need to understand the default network policy behaviors. If no Kubernetes network policies apply to a pod, then all connections to/from the pod are allowed (default-allow). As a result, if you do not create any network policies, then all pods are allowed to communicate freely with all other pods. If one or more Kubernetes network policies apply to a pod, then only the connections specifically defined in that network policy are allowed (default-deny).

You are now ready to start fine-tuning connections that should be allowed. 

- [Create ingress policies](#create-ingress-policies)
- [Allow ingress connections from pods in the same namespace](#allow-ingress-connections-from-pods-in-the-same-namespace)
- [Allow ingress connections from pods in a different namespace](#allow-ingress-connections-from-pods-in-a-different-namespace)
- [Create egress policies](#create-egress-policies)
- [Allow ingress connections from pods in the same namespace](#allow-egress-connections-from-pods-in-the-same-namespace)
- [Allow ingress connections to IP address or CIDR range](#allow-egress-connections-to-ip-address-or-cidr-range)
- [Best practice: create deny-all default network policies](#best-practice-create-deny-all-default-network-policies)
- [Create deny-all default network policy](#create-deny-all-default-network-policy)

#### Create ingress policies

Create ingress network policies to allow inbound connections from other pods. 

Network policies apply to pods within a specific **namespace**. Policies can include one or more ingress rules. To specify which pods in the namespace the network policy applies to, use a **pod selector**. Within the ingress rule, use another pod selector to define which pods allow incoming connections, and the **ports** field to define on which ports connections are allowed. 

##### Allow ingress connections from pods in the same namespace

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

##### Allow ingress connections from pods in a different namespace

To allow connections from pods in a different namespace, use a namespace selector in the ingress policy rule. In the following policy, the namespace selector matches one or more Kubernetes namespaces and is combined with the pod selector that selects pods within those namespaces. 

>**Note**: Namespace selectors can be used only in policy rules. The **spec.podSelector** applies to pods only in the same namespace as the policy.
{: .alert .alert-info}

In the following example, incoming connections are allowed only if they come from a pod with label **color=red**, in a namespace with **shape=square**, on port **80**.

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
      namespaceSelector: {“shape”: “square”}
    to:
      ports:
      - port: 80
```  
{: .no-select-button}

#### Create egress policies

Create egress network policies to allow outbound connections from pods. 

##### Allow egress connections from pods in the same namespace

The following policy allows pod outbound connections to other pods in the same namespace that match the pod selector. In the following example, outbound connections are allowed only if they go to a pod with **color=red**, on port **80**.

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

##### Allow egress connections, pods to IP addresses or CIDR range

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

##### Create deny-all default ingress and egress policy

The following network policy implements a default **deny-all** ingress and egress policy, which prevents all connections to/from pods in the **policy-demo** namespace. Note that the policy applies to all pods in the policy-demo namespace, but does not explicitly allow any connections. All pods are selected, but because the default changes when pods are selected by a network policy, the result is: **deny all ingress and egress connections**. (Unless the connection is allowed by another network policy).

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
{: .no-select-button}

### Above and Beyond

[Kubernetes Network Policy API documentation](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#networkpolicy-v1-networking-k8s-io)


