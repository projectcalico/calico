---
title: Global network set
description: API for this Calico resource.
canonical_url: '/reference/resources/globalnetworkset'
---

A global network set resource (GlobalNetworkSet) represents an arbitrary set of IP subnetworks/CIDRs,
allowing it to be matched by {{site.prodname}} policy.  Network sets are useful for applying policy to traffic
coming from (or going to) external, non-{{site.prodname}}, networks.

The metadata for each network set includes a set of labels.  When {{site.prodname}} is calculating the set of
IPs that should match a source/destination selector within a
[global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) rule, or within a
[network policy]({{ site.baseurl }}/reference/resources/networkpolicy) rule whose `namespaceSelector` includes `global()`, it includes
the CIDRs from any network sets that match the selector.

> **Important**: Since {{site.prodname}} matches packets based on their source/destination IP addresses,
> {{site.prodname}} rules may not behave as expected if there is NAT between the {{site.prodname}}-enabled node and the
> networks listed in a network set.  For example, in Kubernetes, incoming traffic via a service IP is
> typically SNATed by the kube-proxy before reaching the destination host so {{site.prodname}}'s workload
> policy will see the kube-proxy's host's IP as the source instead of the real source.
{: .alert .alert-danger}


### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: a-name-for-the-set
  labels:
    role: external-database
spec:
  nets:
  - 198.51.100.0/28
  - 203.0.113.0/24
```

### Global network set definition

#### Metadata

| Field       | Description                                | Accepted Values                                     | Schema  |
|-------------|--------------------------------------------|-----------------------------------------------------|---------|
| name        | The name of this network set.              | Lower-case alphanumeric with optional `-` or `-`.   | string  |
| labels      | A set of labels to apply to this endpoint. |                                                     | map     |

#### Spec

| Field       | Description                                  | Accepted Values                                         | Schema | Default    |
|-------------|----------------------------------------------|---------------------------------------------------------|--------|------------|
| nets        | The IP networks/CIDRs to include in the set. | Valid IPv4 or IPv6 CIDRs, for example "192.0.2.128/25"  | list   |            |
