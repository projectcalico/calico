---
title: Enforce network policy using Istio
---

### Big picture

Calico integrates seamlessly with Istio to enforce network policy within the Istio service mesh.

### Value

#### Support security goals

Using Calico network policy with Istio enables adoption of a zero trust network model for security, including traffic encryption, multiple enforcement points, and multiple identity criteria for authentication.

#### Familiar policy language

Users do not need to learn another network policy model when adopting Istio. Kubernetes network policies and Calico network policies work as is.

### Features

This how-to guide uses the following Calico features:

**Calico integration with Istio**

### Before you begin...

[Install Calico and calicoctl]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/calico)

### How to

After you complete the steps to [enable application layer policy]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy), you are ready to create standard Calico network policies with application layer specific attributes.

### Above and beyond

- [Use service accounts in policy rules]({{site.baseurl}}/{{page.version}}/security/service-accounts) 
- [Use HTTP methods and paths in policy rules]({{site.baseurl}}/{{page.version}}/security/http-methods)
