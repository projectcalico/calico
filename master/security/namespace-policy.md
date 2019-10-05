---
title: Use namespace in policy rules
description: Use namespaces and namespaceSelectors in Calico network policy to group or separate resources. Use policy rules to allow or deny traffic to/from pods belonging to specific namespaces.
---

### Big picture

Use {{site.prodname}} network policy rules to reference pods in other namespaces.

### Value

Kubernetes namespaces let you group/separate resources to meet a variety of use-cases. For example you can use namespaces to separate development, production, and QA environments, or to allow different teams to use the same cluster. Using namespace selectors in {{site.prodname}} policy rules allows you to allow or deny traffic to/from pods belonging to specific namespaces. 

### Features

This how-to guide uses the following {{site.prodname}} features:

**NetworkPolicy** with namespaceSelector

### How to

#### Control traffic to/from endpoints in a namespace

In the following example, ingress traffic is allowed to endpoints in the **namespace: production** with label **color: red**, and only from a pod in the same namespace with **color: blue**, on **port 6379**.

```
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

```
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
### Above and beyond

- For more network policy rules, see [Network policy]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy)
- To apply policy to all namespaces, see [Global network policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy)
