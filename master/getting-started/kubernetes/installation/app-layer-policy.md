---
title: Enable application layer policy for Istio
canonical_url: 'https://docs.projectcalico.org/v3.9/getting-started/kubernetes/installation/app-layer-policy'
---

### Big picture

Enable {{site.prodname}} application layer network policy in Istio service mesh.

### Value

Enabling {{site.prodname}} application layer policy lets you enforce application layer attributes like HTTP methods or paths, and cryptographically secure identities. 

### Concepts

#### Mitigate threats with {{site.prodname}} network policy

Although Istio policy is ideal for operational goals, security inside and outside the cluster requires {{site.prodname}} network policy. {{site.prodname}} supports a special integration for Istio, called application layer policy. This policy lets you restrict ingress traffic inside and outside pods, and mitigate common threats to Istio-enabled apps.

For a tutorial on how application layer policy provides second-factor authentication for the mythical Yao Bank, see [Enforce network policy using Istio]({{site.url}}/{{page.version}}security/tutorials/app-layer-policy/enforce-policy-istio).

### Before you begin...

**Required**

- [Calio is installed]({{site.url}}/{{page.version}}/getting-started/)
- [calicoctl is installed and configured]({{site.url}}/{{page.version}}/getting-started/calicoctl/install)

### How to

1. [Enable application layer policy](#enable-application-layer-policy)
1. [Install Istio](#install-istio)
1. [Update Istio sidecar injector](#update-istio-sidecar-injector)
1. [Add Calico authorization services to the mesh](#add-calico-authorization-services-to-the-mesh)
1. [Add namespace labels](#add-namespace-labels)

#### Enable application layer policy

#### Install Istio

#### Update Istio sidecar injector

#### Add Calico authorization services to the mesh

#### Add namespace labels

**Note**:
{: .alert .alert-info}

### Above and beyond

- [Enforce network policy using Istio]({{site.url}}/{{page.version}}/security/enforce-policy-istio)
- [Use http methods and paths in policy rules]({{site.url}}/{{page.version}}/security/http-methods)