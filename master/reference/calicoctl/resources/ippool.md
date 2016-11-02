---
title: IP Pool Resource (ipPool)
---

An IP Pool resource (ipPool) represents an IP address pool which Calico uses 
to allocate IP addresses to endpoints/containers. The IP Pool is specified by 
a CIDR (subnet) - this is the set of addresses that may be assigned to 
endpoints.

The full set of IP addresses in the IP Pool subnet should be available for
assignment by Calico.

### Sample YAML

```
apiVersion: v1
kind: pool
metadata:
  cidr: 10.1.0.0/16
spec:
  ipip: 
    enabled: false
  nat-outgoing: true
  disabled: false
```

### Definitions

#### Metadata

| name     | description                     | requirements | schema |
|----------|---------------------------------|--------------|--------|
| cidr     | The CIDR of this pool.          |              | string representation of CIDR |

#### Spec

| name     | description                 | requirements | schema  |
|----------|-----------------------------|--------------|---------|
| ipip | Configuration for ipip tunneling for this pool.     | If not specified, ipip tunneling is disabled for this pool. | [IPIP Configuration](#ipip-configuration) |
| nat-outgoing | When enabled, packets sent from calico networked containers in this pool to destinations outside of this pool will be masqueraded. | | boolean |
| disabled | When set to true, Calico IPAM will not assign addresses from this pool. |     | boolean |

#### IPIP Configuration

| name     | description                 | requirements | schema  |
|----------|-----------------------------|--------------|---------|
| enabled   | When set to true, ipip tunneling will be used to deliver packets to desinations within this pool. |              | boolean |
