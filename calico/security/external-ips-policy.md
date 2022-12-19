---
title: Use external IPs or networks rules in policy
description: Limit egress and ingress traffic using IP address either directly within Calico network policy or managed as Calico network sets.
---

### Big picture

Use {{site.prodname}} network policy to limit traffic to/from external non-{{site.prodname}} workloads or networks.

### Value

Modern applications often integrate with third-party APIs and SaaS services that live outside Kubernetes clusters. To securely enable access to those integrations, network security teams must be able to limit IP ranges for egress and ingress traffic to workloads. This includes using IP lists or ranges to deny-list bad actors or embargoed countries.

Using {{site.prodname}} network policy, you can define IP addresses/CIDRs directly in policy to limit traffic to external networks. Or using {{site.prodname}} network sets, you can easily scale out by using the same set of IPs in multiple policies. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- **GlobalNetworkSet** or **NetworkSet** to specify IPs/CIDRs to use in policy
- **GlobalNetworkPolicy** or **NetworkPolicy** to limit traffic to external networks using IP addresses or network sets

### Concepts

#### IP addresses/CIDRs

IP addresses and CIDRs can be specified directly in both Kubernetes and {{site.prodname}} network policy rules. {{site.prodname}} network policy supports IPV4 and IPV6 CIDRs. 

#### Network sets

A **network set** resource is an arbitrary set of IP subnetworks/CIDRs that can be matched by standard label selectors in Kubernetes or {{site.prodname}} network policy. This is useful to reference a set of IP addresses using a selector from a namespaced network policy resource. It is typically used when you want to scale/reuse the same set of IP addresses in policy. 

A **global network set** resource is similar, but can be selected only by {{site.prodname}} global network policies.

### How to

- [Limit traffic to or from external networks, IPs in network policy](#limit-traffic-to-or-from-external-networks-ips-in-network-policy)
- [Limit traffic to or from external networks, global network set](#limit-traffic-to-or-from-external-networks-global-network-set)

#### Limit traffic to or from external networks, IPs in network policy

In the following example, a {{site.prodname}} NetworkPolicy allows egress traffic from pods with the label **color: red**, if it goes to an IP address in the 192.0.2.0/24 CIDR block.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-egress-external
  namespace: production
spec:
  selector:
    color == 'red'
  types:
    - Egress
  egress:    
    - action: Allow
      destination:
        nets:
        - 192.0.2.0/24
```

#### Limit traffic to or from external networks, global network set 

In this example, we use a {{site.prodname}} **GlobalNetworkSet** and reference it in a **GlobalNetworkPolicy**.

In the following example, a {{site.prodname}} **GlobalNetworkSet** deny-lists the CIDR ranges 192.0.2.55/32 and 203.0.113.0/24:

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: ip-protect
  labels:
    ip-deny-list: "true"
spec:
  nets:
  - 192.0.2.55/32
  - 203.0.113.0/24
```

Next, we create two {{site.prodname}} **GlobalNetworkPolicy** objects. The first is a high “order” policy that allows traffic as a default for things that don’t match our second policy, which is low “order” and uses the **GlobalNetworkSet** label as a selector to deny ingress traffic (IP-deny-list in the previous step). In the label selector, we also include the term **!has(projectcalico.org/namespace)**, which prevents this policy from matching pods or NetworkSets that also have this label. To more quickly enforce the denial of forwarded traffic to the host at the packet level, use the **doNotTrack** and **applyOnForward** options.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: forward-default-allow
spec:
  selector: apply-ip-protect == 'true'
  order: 1000
  doNotTrack: true
  applyOnForward: true
  types:
  - Ingress
  ingress:
  - action: Allow
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: ip-protect
spec:
  selector: apply-ip-protect == 'true'
  order: 0
  doNotTrack: true
  applyOnForward: true
  types:
  - Ingress
  ingress:
  - action: Deny
    source:
      selector: ip-deny-list == 'true' && !has(projectcalico.org/namespace)
```

### Above and beyond

-  To understand how to use global network sets to mitigate common threats, see [Defend against DoS attacks]({{ site.baseurl }}/security/defend-dos-attack)
- [Global network sets]({{ site.baseurl }}/reference/resources/globalnetworkset)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)