---
title: IP reservation
description: API for this Calico resource.
canonical_url: '/reference/resources/ipreservation'
---

An IP reservation resource (`IPReservation`) represents a collection of IP addresses that {{site.prodname}} should 
not use when automatically assigning new IP addresses.  It only applies when {{site.prodname}} IPAM is in use.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: IPReservation
metadata:
  name: my-ipreservation-1
spec:
  reservedCIDRs:
  - 192.168.2.3
  - 10.0.2.3/32
  - cafe:f00d::/123
```

### IP reservation definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     |  The name of this IPReservation resource. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field          | Description                 | Accepted Values   | Schema | Default    |
|----------------|-----------------------------|-------------------|--------|------------|
| reservedCIDRs  | List of IP addresses and/or networks specified in CIDR notation  | List of valid IP addresses (v4 or v6) and/or CIDRs | list | |

#### Notes

The implementation of `IPReservation`s is designed to handle reservation of a small number of IP addresses/CIDRs from
(generally much larger) IP pools.  If a significant portion of an IP pool is reserved (say more than 10%) then 
{{site.prodname}} may become significantly slower when searching for free IPAM blocks.

Since `IPReservations` must be consulted for every IPAM assignment request, it's best to have one or two 
`IPReservation` resources with multiple addresses per `IPReservation` resource (rather than having many IPReservation
resources), each with one address inside.

If an `IPReservation` is created after an IP from its range is already in use then the IP is not automatically 
released back to the pool.  The reservation check is only done at auto allocation time.

{{site.prodname}} supports Kubernetes [annotations that force the use of specific IP addresses](../cni-plugin/configuration#requesting-a-specific-ip-address). These annotations override any `IPReservation`s that 
are in place.

When Windows nodes claim blocks of IPs they automatically assign the first three IPs
in each block and the final IP for internal purposes.  These assignments cannot be blocked by an `IPReservation`.
However, if a whole IPAM block is reserved with an `IPReservation`, Windows nodes will not claim such a block.
