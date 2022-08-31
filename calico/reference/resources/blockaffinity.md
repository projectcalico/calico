---
title: Block affinity
description: IP address management block affinity
canonical_url: '/reference/resources/blockaffinity'
---

A block affinity resource (`BlockAffinity`) represents the affinity for an IPAM block. These are managed by Calico IPAM.

### Block affinity definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name        | Unique name to describe this resource instance. Must be specified.| Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| state       | State of the affinity with regard to any referenced IPAM blocks. | confirmed, pending, pendingDeletion | string | |
| node        | The node that this affinity is assigned to. | The hostname of the node | string | |
| cidr        | The CIDR range this block affinity references. | A valid IPv4 or IPv6 CIDR. | string | |
| deleted     | When set to true, clients should treat this block as if it does not exist. | true, false | boolean | `false` |

### Supported operations

| Datastore type        | Create     | Delete    | Update  | Get/List | Watch |
|-----------------------|------------|-----------|---------|----------|-------|
| etcdv3                | No         | No        | No      | Yes      | Yes   |
| Kubernetes API server | No         | No        | No      | Yes      | Yes   |
