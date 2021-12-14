---
title: Use HTTP methods and paths in policy rules
description: Create a Calico network policy for Istio-enabled apps to restrict ingress traffic matching HTTP methods or paths.
---

### Big picture

Use Calico network policy for Istio-enabled apps to restrict ingress traffic that matches HTTP methods or paths.

### Value

Istio is ideal for applying policy for operational goals and for security that operates at the application layer. However, for security goals inside and outside the cluster, Calico network policy is required. Using special Calico network policy designed for Istio-enabled apps, you can restrict ingress traffic inside and outside pods using HTTP methods (for example, GET requests).

### Features

This how-to guide uses the following Calico features:

- **NetworkPolicy** and **GlobalNetworkPolicy** with http match criteria to restrict traffic using:
  - Standard HTTP methods
  - Paths (exact and prefix)

### Concepts

#### HTTP match criteria: ingress traffic only 

Calico network policy supports restricting traffic based on HTTP methods and paths only for ingress traffic.

### Before you begin...

[Enable application layer policy[Enable application layer policy]({{site.baseurl}}/security/app-layer-policy)

### How to

**Restrict ingress traffic using HTTP match criteria**

In the following example, the trading app is allowed ingress traffic only for HTTP GET requests that match the exact path **/projects/calico**, or that begins with the prefix, **/users**.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: customer
spec:
  selector: app == 'tradingapp'
  ingress:
   - action: Allow
     http:
       methods: ["GET"]
       paths:
         - exact: "/projects/calico"
         - prefix: "/users"
  egress:
    - action: Allow
```
