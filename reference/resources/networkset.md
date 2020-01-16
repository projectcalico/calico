---
title: Network set
description: API for this Calico resource.
canonical_url: '/reference/resources/networkset'
---

A network set resource (NetworkSet) represents an arbitrary set of IP subnetworks/CIDRs,
allowing it to be matched by {{site.prodname}} policy.  Network sets are useful for applying policy to traffic
coming from (or going to) external, non-{{site.prodname}}, networks.

`NetworkSet` is a namespaced resource. `NetworkSets` in a specific namespace
only applies to [network policies]({{ site.baseurl }}/reference/resources/networkpolicy)
in that namespace. Two resources are in the same namespace if the `namespace`
value is set the same on both. (See [GlobalNetworkSet]({{ site.baseurl }}/reference/resources/globalnetworkset) for non-namespaced network sets.)

The metadata for each network set includes a set of labels.  When {{site.prodname}} is calculating the set of
IPs that should match a source/destination selector within a
[network policy]({{ site.baseurl }}/reference/resources/networkpolicy) rule, it includes
the CIDRs from any network sets that match the selector.

> **Important**: Since {{site.prodname}} matches packets based on their source/destination IP addresses,
> {{site.prodname}} rules may not behave as expected if there is NAT between the {{site.prodname}}-enabled node and the
> networks listed in a network set.  For example, in Kubernetes, incoming traffic via a service IP is
> typically SNATed by the kube-proxy before reaching the destination host so {{site.prodname}}'s workload
> policy will see the kube-proxy's host's IP as the source instead of the real source.
{: .alert .alert-danger}

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `networkset`, `networksets`, `netsets`.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: external-database
  namespace: staging
  labels:
    role: db
spec:
  nets:
  - 198.51.100.0/28
  - 203.0.113.0/24
```

### Network set definition

#### Metadata

| Field     | Description                                                        | Accepted Values                                   | Schema | Default   |
|-----------|--------------------------------------------------------------------|---------------------------------------------------|--------|-----------|
| name      | The name of this network set. Required.                            | Lower-case alphanumeric with optional `_` or `-`. | string |           |
| namespace | Namespace provides an additional qualification to a resource name. |                                                   | string | "default" |
| labels    | A set of labels to apply to this endpoint.                         |                                                   | map    |           |

#### Spec

| Field       | Description                                  | Accepted Values                                         | Schema | Default    |
|-------------|----------------------------------------------|---------------------------------------------------------|--------|------------|
| nets        | The IP networks/CIDRs to include in the set. | Valid IPv4 or IPv6 CIDRs, for example "192.0.2.128/25"  | list   |            |
