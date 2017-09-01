---
title: Network Set Resource (networkSet)
---

A network set resource (networkSet) represents an arbitrary set of IP subnetworks/CIDRs, allowing it
to be matched by Calico policy.  Network sets are useful for applying policy to traffic
coming from (or going to) external, non-Calico, networks.

The metadata for each network set includes a set of labels.  When Calico is calculating the set of
IPs that should match a source/destination selector within a
[policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) rule, it includes
the CIDRs from any network sets that match the selector.

> **NOTE** Since Calico matches packets based on their source/destination IP addresses, Calico
> rules may not behave as expected if there is NAT between the Calico-enabled node and the
> networks listed in a network set.  For example, in Kubernetes, incoming traffic via a service IP is
> typically SNATed by the kube-proxy before reaching the destination host so Calico's policy will see
> the kube-proxy's host's IP as the source instead of the real source.

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `networkset`, `networksets`, `netset`, `netsets`.

### Sample YAML

```yaml
apiVersion: v1
kind: networkSet
metadata:
  name: my-external-mysql-cluster
  labels:
    role: database
spec:
  nets:
  - "192.0.2.128/25"
  - "192.51.100.123/32"
```

### NetworkSet Definition

#### Metadata

| Field       | Description                                | Accepted Values   | Schema  |
|-------------|--------------------------------------------|-------------------|---------|
| name        | The name of this networkSet.               |                   | string  |
| labels      | A set of labels to apply to this endpoint. |                   | map     |

#### Spec

| Field       | Description                                  | Accepted Values                                         | Schema | Default    |
|-------------|----------------------------------------------|---------------------------------------------------------|--------|------------|
| nets        | The IP networks/CIDRs to include in the set. | Valid IPv4 or IPv6 CIDRs, for example "192.0.2.128/25"  | list   |            |