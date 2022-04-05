---
title: Schedule Typha for scaling to well-known nodes
description: Configure the Calico Typha TCP port.
canonical_url: '/security/comms/reduce-nodes'
---

### Big picture

Schedule Typha to well-known nodes.

### Value

By scheduling Typha to well-known nodes, you can reduce the number of nodes which expose
Typha's listen port.

### Concepts

#### Typha

Typha is a {{site.prodname}} component which improves scalability and reduces the impact that
large clusters may have on the Kubernetes API. Typha agents must accept connections from other agents on a fixed port.

As part of the {{site.prodname}} bootstrap infrastructure, Typha must be available before
pod networking begins and uses host networking instead. It opens a port on the node it is
scheduled on. By default, it can get scheduled to any node and opens TCP 5473.


### How to

#### Tell if you have installed Typha

{% tabs %}
  <label:Operator,active:true>
<%

Operator based installations always include Typha.

%>
  <label:Manifest>
<%

Check if the `calico-typha` deployment exists in the `kube-system` namespace.

```
kubectl get deployment -n kube-system calico-typha
```

%>
{% endtabs %}

#### Schedule Typha to well-known nodes

{% tabs %}
  <label:Operator,active:true>
<%

You can use the Installation API to configure a node affinity for Typha pods. The operator supports both
`preferredDuringSchedulingIgnoredDuringExecution` and `requiredDuringSchedulingIgnoredDuringExecution` options.

For example, to require the scheduler to place Typha on nodes with the label "typha=allowed":

```yaml
kind: Installation
apiVersion: operator.tigera.io/v1
metadata:
  name: default
spec:
  typhaAffinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
      - matchExpressions:
     	- key: typha
          operator: In
          values:
          - allowed
```

%>
  <label:Manifest>
<%

See [scheduling Typha to well-known nodes](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/){:target="_blank"}.

%>
{% endtabs %}
