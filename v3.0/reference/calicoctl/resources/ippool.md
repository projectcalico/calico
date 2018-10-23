---
title: IP Pool Resource (IPPool)
canonical_url: https://docs.projectcalico.org/v3.3/reference/calicoctl/resources/ippool
---

An IP pool resource (`IPPool`) represents a collection of IP addresses from which Calico expects
endpoint IPs to be assigned.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `ippool`, `ippools`, `ipp`, `ipps`, `pool`, `pools`.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: my.ippool-1
spec:
  cidr: 10.1.0.0/16
  ipipMode: CrossSubnet
  natOutgoing: true
  disabled: false
```

### IP Pool Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     |  The name of this IPPool resource. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| cidr     | IP range to use for this pool.  | A valid IPv4 or IPv6 CIDR. Subnet length must be `/26` or less for IPv4 and `/122` or less for IPv6. Must not overlap with the Link Local range `169.254.0.0/16` or `fe80::/10`. | string | |
| ipipMode | The IPIP mode defining when IPIP will be used. | Always, CrossSubnet, Never | string| `Never` |
| natOutgoing | When enabled, packets sent from calico networked containers in this pool to destinations outside of this pool will be masqueraded. | true, false | boolean | `false` |
| disabled | When set to true, Calico IPAM will not assign addresses from this pool. | true, false | boolean | `false` |

Routing of packets using IP-in-IP will be used when the destination IP address
is in an IP Pool that has IPIP enabled.  In addition, if the `ipipMode` is set to `CrossSubnet`,
Calico will only route using IP-in-IP if the IP address of the destination node is in a different
subnet. The subnet of each node is configured on the node resource (which may be automatically
determined when running the calico/node service).

For details on configuring IP-in-IP on your deployment, please read the
[Configuring IP-in-IP guide]({{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip).

> **Note**: Setting `natOutgoing` is recommended on any IP Pool with `ipip` enabled.
When `ipip` is enabled without `natOutgoing` routing between Workloads and
Hosts running Calico is asymmetric and may cause traffic to be filtered due to
[RPF](https://en.wikipedia.org/wiki/Reverse_path_forwarding) checks failing.
{: .alert .alert-info}


### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |
