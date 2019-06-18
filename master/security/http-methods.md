---
title: Using HTTP methods and paths in policy rules
---

### Big picture

Use Calico network policy for Istio-enabled apps to restrict ingress traffic that match HTTP methods or paths. 

### Value

Customer-facing applications (like web apps) can benefit from selective restrictions on ingress traffic (for example, HTTP GET requests). 

### Features

This how-to guide uses the following Calico features:

- **NetworkPolicy** 
- **GlobalNetworkPolicy** with http match criteria to restrict traffic using:
  - Standard HTTP methods
  - Paths (exact and prefix)

### Concepts

#### HTTP match criteria: ingress traffic only 

Calico network policy supports restricting traffic based on HTTP methods and paths only for ingress traffic. 

### Before you begin...

[Enable application layer policy]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy)

### How to

**Restrict ingress traffic using HTTP match criteria**

In the following example, the trading app is allowed ingress traffic only for HTTP GET requests that match the exact path **/projects/calico**, or that begins with the prefix, **/users**.

```
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