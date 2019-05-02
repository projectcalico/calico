---
title: IP Pool Resource (ipPool)
canonical_url: 'https://docs.projectcalico.org/v3.7/reference/calicoctl/resources/ippool'
---

An IP pool resource (ipPool) represents a collection of IP addresses from which Calico expects
endpoint IPs to be assigned.

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `ippool`, `ippools`, `ipp`, `ipps`, `pool`, `pools`.

### Sample YAML

```yaml
apiVersion: v1
kind: ipPool
metadata:
  cidr: 10.1.0.0/16
spec:
  ipip:
    enabled: false
  nat-outgoing: true
  disabled: false
```

### IP Pool Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| cidr     | IP range to use for this pool.  | A valid IPv4 or IPv6 CIDR. | string |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| ipip | ipip tunneling configuration for this pool. If not specified, ipip tunneling is disabled for this pool. | | [IPIP](#ipip) |
| nat-outgoing | When enabled, packets sent from calico networked containers in this pool to destinations outside of this pool will be masqueraded. | true, false | boolean | false
| disabled | When set to true, Calico IPAM will not assign addresses from this pool. | true, false | boolean | false

#### IPIP

| Field    | Description                 | Accepted Values | Schema  | Default    |
|----------|-----------------------------|--------------|---------|------------|
| enabled   | When set to true, ipip encapsulation will be used. | true, false | boolean | true
