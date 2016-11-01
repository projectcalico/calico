---
title: IP Pool resource (ipPool)
---
An IPPool resource represents an IP address pool which Calico-CNI uses to allocate IP addresses to endpoints/containers. IPPool configuration requires a pool name and CIDR (subnet) for the IP pool.

### Sample YAML
```
apiVersion: v1
kind: pool
metadata:
  name: pool1
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
|----------|---------------------------------|--|--------|
| name     | The name of this pool resource. |  | string |
| cidr     | The CIDR of this pool.         |  | string representation of CIDR |

#### Spec

| name     | description                 | requirements | schema  |
|----------|-----------------------------|---------|---------|
| ipip | Configuration for ipip tunneling for this pool.     | If not specified, ipip tunneling is disabled for this pool. | [IPIP Configuration](#ipip-configuration) |
| nat-outgoing | When enabled, packets sent from calico networked containers in this pool to destinations outside of this pool will be masqueraded. | | boolean |
| disabled | When set to true, Calico IPAM will not assign addresses from this pool. |     | boolean |

#### IPIP Configuration

| name     | description                 | requirements | schema  |
|----------|-----------------------------|--------------|---------|
| enabled   | When set to true, ipip tunneling will be used to deliver packets to desinations within this pool. |              | boolean |
