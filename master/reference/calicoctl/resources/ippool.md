---
title: IP pool
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/calicoctl/resources/ippool'
---

An IP pool resource (`IPPool`) represents a collection of IP addresses from which {{site.prodname}} expects
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
  nodeSelector: all()
```

### IP pool definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     |  The name of this IPPool resource. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| cidr     | IP range to use for this pool.  | A valid IPv4 or IPv6 CIDR. Subnet length must be at least big enough to fit a single block (by default `/26` for IPv4 or `/122` for IPv6). Must not overlap with the Link Local range `169.254.0.0/16` or `fe80::/10`. | string | |
| blockSize | The CIDR size of allocation blocks used by this pool. Blocks are allocated on demand to hosts and are used to aggregate routes. The value can only be set when the pool is created. | 20 to 32 (inclusive) for IPv4 and 116 to 128 (inclusive) for IPv6 | int| `26` for IPv4 pools and `122` for IPv6 pools. |
| ipipMode | The mode defining when IPIP will be used. Cannot be set at the same time as `vxlanMode`. | Always, CrossSubnet, Never | string| `Never` |
| vxlanMode | The mode defining when VXLAN will be used. Cannot be set at the same time as `ipipMode`. | Always, Never | string| `Never` |
| natOutgoing | When enabled, packets sent from {{site.prodname}} networked containers in this pool to destinations outside of this pool will be masqueraded. | true, false | boolean | `false` |
| disabled | When set to true, {{site.prodname}} IPAM will not assign addresses from this pool. | true, false | boolean | `false` |
| nodeSelector | Selects the nodes that {{site.prodname}} IPAM should assign addresses from this pool to. | | [selector](#node-selector) | all() |

> **Important**: Do not use a custom `blockSize` until **all** {{site.prodname}} components have been updated to a version that
> supports it (at least v3.3.0).  Older versions of components do not understand the field so they may corrupt the
> IP pool by creating blocks of incorrect size.
{: .alert .alert-danger}

#### IPIP

Routing of packets using IP-in-IP will be used when the destination IP address
is in an IP Pool that has IPIP enabled.  In addition, if the `ipipMode` is set to `CrossSubnet`,
{{site.prodname}} will only route using IP-in-IP if the IP address of the destination node is in a different
subnet. The subnet of each node is configured on the node resource (which may be automatically
determined when running the `{{site.nodecontainer}}` service).

For details on configuring IP-in-IP on your deployment, please refer to
[Configuring IP-in-IP]({{site.baseurl}}/{{page.version}}/networking/ip-in-ip).


> **Note**: Setting `natOutgoing` is recommended on any IP Pool with `ipip` enabled.
When `ipip` is enabled without `natOutgoing` routing between Workloads and
Hosts running {{site.prodname}} is asymmetric and may cause traffic to be filtered due to
[RPF](https://en.wikipedia.org/wiki/Reverse_path_forwarding) checks failing.
{: .alert .alert-info}

#### VXLAN

Similarly to IP-in-IP, if `vxlanMode` is set to `Always`, VXLAN encapsulation will be used if the IP of the 
destination is within the pool.

`CrossSubnet` mode is not supported with VXLAN in this release.

> **Note**: As with IP-in-IP, setting `natOutgoing` is recommended on any IP Pool with `VXLAN` enabled.
{: .alert .alert-info}

#### Block sizes
The default block sizes of `26` for IPv4 and `122` for IPv6 provide blocks of 64 addresses. This allows addresses to be allocated in groups to workloads running on the same host. By grouping addresses, fewer routes need to be exchanged between hosts and to other BGP peers. If a host allocates all of the addresses in a block then it will be allocated an additional block. If there are no more blocks available then the host can take addresses from blocks allocated to other hosts. Specific routes are added for the borrowed addresses which has an impact on route table size.

Increasing the block size from the default (e.g., using `24` for IPv4 to give 256 addresses per block) means fewer blocks per host, and potentially fewer routes. But try to ensure that there are at least as many blocks in the pool as there are hosts.

Reducing the block size from the default (e.g., using `28` for IPv4 to give 16 addresses per block) means more blocks per host and therefore potentially more routes. This can be beneficial if it allows the blocks to be more fairly distributed amongst the hosts.

#### Node Selector

{% include {{page.version}}/selectors.md %}

For details on configuring IP pool node selectors, please read the
[Assigning IP addresses based on topology guide.]({{site.baseurl}}/{{page.version}}/networking/assigning-ip-addresses-topology).

> **Note**: The pool's `disabled` field takes higher precedence than
> `nodeSelector`. This means that {{site.prodname}} IPAM will not allocate any
> IPs from a disabled pool even if it selects the node that it is on.
{: .alert .alert-info}

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |
