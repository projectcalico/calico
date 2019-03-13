template stuff


### Big Picture

Kubernetes network policy lets you enforce network traffic patterns using rules. 

### Value

Kubernetes network policy lets developers secure access to and from their applications using the same, simple language they use to deploy them. Developers can focus on their applications without needing to understand low-level networking concepts. Enabling developers to easily secure their applications in this way, supports a shift left DevOps environment. 

### Features

The Kubernetes Network Policy API supports: 

Network policies that are:
- Namespace scoped
- Applied to pods using label selectors

Network policy rules that specify:
- Ingress/egress connections that are allowed to/from pods, namespaces, or CIDRs
- Protocols (STCP)
- Named ports or port numbers

### Concepts

Calico supports the complete Kubernetes network policy API, and extends it with additional policy features. For details, see Calico Network Policy.

The Kubernetes Network Policy API lets users specify rules for controlling network traffic. It provides L3/L4 IP address and port-based network segmentation. However, to enforce the network policy rules, you need a network plugin like Calico.

#### Ingress and Egress

The bulk of securing network traffic typically revolves around defining egress and ingress rules. Ingress is incoming connections to a Kubernetes pod. Egress is outgoing connections from a Kubernetes pod. In network policy you create ingress and egress “allow” rules, which you can apply independently (egress, ingress, or both). 

#### Default deny/allow 

**Default allow** means all connections are allowed by default, unless otherwise specified. **Default deny** means all connections are denied by default, unless explicitly allowed. 

### How to

Before you create your first network policy, you need to understand the default network policy behaviors. 
- If you do not create any Kubernetes network policies, then all pods are allowed to communicate with all other pods. 
- When you create one or more network policies, any connections that are not explicitly allowed by the policy are treated as **default-deny** when pods are selected. 

You ready now ready to start fine-tuning what traffic should be allowed. 

Create ingress policies
Allow ingress traffic, same namespace
Allow ingress traffic, different namespace
Create egress policies
Allow ingress traffic, same namespace
Allow ingress traffic, by IP address or CIDR range
Best practice: create deny-all default network policies
Create deny-all default ingress policy, all pods in a namespace
Create deny-all default egress policy, all pods in a namespace

#### Create ingress policies

Create ingress network policies to allow inbound traffic from other pods. 

Network policies apply to pods within a specific namespace. Policies can include one or more ingress rules. To specify which pods in the namespace the network policy applies to, use a pod selector, and a ports: field to define which ports should be allowed. 

##### Allow ingress traffic, pods in same namespace

In the following example, incoming traffic to pods with label color=blue is allowed only if it comes from a pod with **color=red**, on port **80**.

```kind: NetworkPolicy
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
      - port: **80**
```
##### Allow ingress traffic, pods in a different namespace

To allow traffic from pods in a different namespace, use a namespace selector. In the following policy, the namespace selector matches one or more Kubernetes namespaces and is combined with the pod selector. 

>**Note**: Namespace selectors can only be used in policy rules. The spec.podSelector applies only to pods in the same namespace as the policy.
{: .alert .alert-info}

In the following example, incoming traffic is allowed only if it comes from a pod with color=red, in a namespace with **something=else**, on port **80**.

```kind: NetworkPolicy
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
      - port: **80**
```      

#### Create egress policies

Create egress network policies to allow outbound traffic from pods. 

##### Allow egress traffic, same namespace

The following policy allows pod outbound traffic to other pods in the same namespace that match the pod selector. In the following example, traffic is allowed only if it is going to a pod with **color=red**, on port **80**.

```kind: NetworkPolicy
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
      
##### Allow egress traffic, IP address or CIDR ranges

Egress policies can also be used to allow traffic to specific IP addresses and CIDR ranges. Typically, IP addresses/ranges are used to handle traffic external to the cluster for static resources or subnets. 

The following policy allows traffic to the IP address range, **172.18.0.0/24**.

```kind: NetworkPolicy
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

#### Best practice: create deny-all default network policies

To ensure that all pods in the namespace are secure, a best practice is to create a default network policy. This avoids accidentally exposing an app or version that doesn’t have policy defined. 

##### Create deny-all default ingress and egress policy, all pods in a namespace

The following network policy implements a default, **deny-all** ingress and egress policy that prevents all traffic to pods in the policy-demo namespace. The policy applies to all pods in the **policy-demo** namespace, but does not explicitly allow any traffic. All pods are selected, but because the default changes when pods are selected by a network policy, the result is: deny all ingress and egress traffic. (Unless the traffic is allowed by another network policy).

```kind: NetworkPolicy
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

### Above and Beyond

[Kubernetes Network Policy API documentation](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#networkpolicy-v1-networking-k8s-io).


