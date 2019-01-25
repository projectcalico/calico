---
title: IP Pool Resource (ipPool)
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/calicoctl/resources/ippool'
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
    enabled: true
    mode: cross-subnet
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
| enabled  | When set to true, ipip encapsulation will be used. | true, false | boolean | true |
| mode     | The IPIP mode defining when IPIP will be used.     | always, cross-subnet | string | always |

Routing of packets using IP in IP will be used when the destination IP address
is in an IP Pool that has IPIP enabled.  In addition, if the `mode` is set to `cross-subnet`,
Calico will only route using IP in IP if the IP address of the destination node is in a different
subnet.  The subnet of each node is configured on the node resource (which may be automatically 
determined when running the calico/node service).

For details on configuring IP-in-IP on your deployment, please read the
[Configuring IP-in-IP guide]({{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip).

> **NOTE**
>
> Setting `nat-outgoing` is recommended on any IP Pool with `ipip` enabled.
When `ipip` is enabled without `nat-outgoing` routing between Workloads and
Hosts running Calico is asymmetric and may cause traffic to be filtered due to
[RPF](https://en.wikipedia.org/wiki/Reverse_path_forwarding) checks failing.
