---
title: Use namespace rules in policy
description: Use namespaces and namespace selectors in Calico network policy to group or separate resources. Use network policies to allow or deny traffic to/from pods that belong to specific namespaces.
---

### Big picture

Use {{site.prodname}} network policies to reference pods in other namespaces.

### Value

Kubernetes namespaces let you group/separate resources to meet a variety of use cases. For example, you can use namespaces to separate development, production, and QA environments, or allow different teams to use the same cluster. You can use namespace selectors in {{site.prodname}} network policies to allow or deny traffic to/from pods in specific namespaces.

### Features

This how-to guide uses the following {{site.prodname}} features:

**NetworkPolicy** with namespaceSelector

### How to

- [Control traffic to/from endpoints in a namespace](#control-traffic-tofrom-endpoints-in-a-namespace)
- [Use Kubernetes RBAC to control namespace label assignment](#use-kubernetes-rbac-to-control-namespace-label-assignment)

#### Control traffic to/from endpoints in a namespace

In the following example, ingress traffic is allowed to endpoints in the **namespace: production** with label **color: red**, and only from a pod in the same namespace with **color: blue**, on **port 6379**.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-tcp-6379
  namespace: production
spec:
  selector: color == 'red'
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: color == 'blue'
    destination:
      ports:
        - 6379
```
To allow ingress traffic from endpoints in other namespaces, use a **namespaceSelector** in the policy rule. A namespaceSelector matches one or more namespaces based on the labels that are applied on the namespace. In the following example, ingress traffic is also allowed from endpoints with **color: blue** in namespaces with **shape: circle**.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-tcp-6379
  namespace: production
spec:
  selector: color == 'red'
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: color == 'blue'
      namespaceSelector: shape == 'circle'
    destination:
      ports:
      - 6379
```

#### Use Kubernetes RBAC to control namespace label assignment

Network policies can be applied to endpoints using selectors that match labels on the endpoint, the endpoint's namespace, or the endpoint's service account. By applying selectors based on the endpoint's namespace, you can use Kubernetes RBAC to control which users can assign labels to namespaces. This allows you to separate groups who can deploy pods from those who can assign labels to namespaces.

In the following example, users in the development environment can communicate only with pods that have a namespace labeled, `environment == "development"`.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-development-access
spec:
  namespaceSelector: 'environment == "development"'
  ingress:
    - action: Allow
      source:
        namespaceSelector: 'environment == "development"'
  egress:
    - action: Allow
      destination:
        namespaceSelector: 'environment == "development"'
```

### Above and beyond

- For more network policies, see [Network policy]({{ site.baseurl }}/reference/resources/networkpolicy)
- To apply policy to all namespaces, see [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
