---
title: Advanced egress access controls
description: Use Calico Enterprise DNS-based policy for fine-grained access control between a pod and external services.
calico_enterprise: true
---

### Egress access control to external endpoints

Fine-grained access control between a pod and external service outside the cluster generally requires a firewall rule or equivalent between your pod and the services you need to connect to. Since traditional firewall rules are defined using static IP addresses, the dynamic nature of pod IP assignment creates challenges in defining firewall rules. Kubernetes/Calico network policies are designed to abstract away from IP addresses in favor of label selectors, but still require external services outside of the cluster to be identified by IP address.

Calico Enterprise extends Calico’s policy model so that domain names (FQDN / DNS) can be used to allow access from a pod or set of pods (via label selector) to external resources outside of your cluster. Common use cases for domain name based policy include:

- Your application may be stateful and require pod-level access to a database running outside of the cluster
- Your application may use cloud services (database services, caching services, file storage, etc.) and require access pod-level to those services
- Your application may use third-party API services (Twilio, Stripe, etc.) and require pod-level access to those services

Domain name based policies enable fine-grained controls that are enforced at the source Pod rather than a firewall rule or equivalent.

DNS endpoints can be defined as an exact address (e.g. google.com) or can include wildcards (e.g. `*.google.com`). DNS endpoints can also be used within [Global Network Sets]({{site.baseurl}}/reference/resources/globalnetworkset).

![dns-policy-rules]({{site.baseurl}}/images/dns-policy-rules.png)
