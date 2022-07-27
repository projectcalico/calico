---
title: IPAM configuration
description: IP address management global configuration
canonical_url: '/reference/resources/ipamconfig'
---

A IPAM configuration resource (`IPAMConfiguration`) represents global IPAM configuration options.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: IPAMConfiguration
metadata:
  name: default
spec:
  strictAffinity: false
  maxBlocksPerHost: 4
```

### IPAM configuration definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Required. | default | string |

The resource is a singleton which must have the name `default`.

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| strictAffinity | When StrictAffinity is true, borrowing IP addresses is not allowed. | true, false | bool | false |
| maxBlocksPerHost | The max number of blocks that can be affine to each host. | 0 - max(int32) | int | unlimited |

### Supported operations

| Datastore type        | Create     | Delete    | Update  | Get/List |
|-----------------------|------------|-----------|---------|----------|
| etcdv3                | Yes        | Yes       | Yes     | Yes      |
| Kubernetes API server | Yes        | Yes       | Yes     | Yes      |
