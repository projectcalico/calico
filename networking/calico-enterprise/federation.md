---
title: Federation
description: Federated services provide service discovery of remote pods in another cluster. 
calico_enterprise: true
---

With Calico Enterprise, you can create policies in one cluster that reference pods in another cluster using federated identity. Federated services provide service discovery of remote pods in another cluster. With these two features you can define fine-grained security controls between multiple clusters.

![federated-endpoint-identity]({{site.baseurl}}/images/federated-endpoint-identity.png)

### Federated tiers and policies

Using federated tiers and federated policies, you can define security policies that apply across all clusters, or to a specific group of clusters. If you plan to deploy multiple clusters, federated tiers and policies you can extend your security controls to each existing and new cluster. This reduces duplication of policies (and maintenance of identical policies per cluster) to simplify the creation and maintenance of your security controls.

![policy-federation]({{site.baseurl}}/images/policy-federation.png)