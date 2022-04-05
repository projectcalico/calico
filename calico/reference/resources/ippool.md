---
title: IP pool
description: API for this Calico resource.
canonical_url: '/reference/resources/ippool'
---

An IP pool resource (`IPPool`) represents a collection of IP addresses from which {{site.prodname}} expects
endpoint IPs to be assigned.

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
  allowedUses:
  - Workload
  - Tunnel 
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
| vxlanMode | The mode defining when VXLAN will be used. Cannot be set at the same time as `ipipMode`. | Always, CrossSubnet, Never | string| `Never` |
| natOutgoing | When enabled, packets sent from {{site.prodname}} networked containers in this pool to destinations outside of any Calico IP pools will be masqueraded. | true, false | boolean | `false` |
| disabled | When set to true, {{site.prodname}} IPAM will not assign addresses from this pool. | true, false | boolean | `false` |
| disableBGPExport _(since v3.21.0)_ | Disable exporting routes from this IP Pool’s CIDR over BGP. | true, false | boolean | `false` |
| nodeSelector | Selects the nodes that {{site.prodname}} IPAM should assign addresses from this pool to. | | [selector](#node-selector) | all() |
| allowedUses _(since v3.21.0)_ | Controls whether the pool will be used for automatic assignments of certain types.  See [below](#allowed-uses). | Workload, Tunnel | list of strings | `["Workload", "Tunnel"]` |

> **Important**: Do not use a custom `blockSize` until **all** {{site.prodname}} components have been updated to a version that
> supports it (at least v3.3.0).  Older versions of components do not understand the field so they may corrupt the
> IP pool by creating blocks of incorrect size.
{: .alert .alert-danger}

#### Allowed uses

When automatically assigning IP addresses to workloads, only pools with "Workload" in their `allowedUses` field are 
consulted.  Similarly, when assigning IPs for tunnel devices, only "Tunnel" pools are eligible.

If the `allowedUses` field is not specified, it defaults to `["Workload", "Tunnel"]` for compatibility with older
versions of Calico.  It is not possible to specify a pool with no allowed uses. 

The `allowedUses` field is only consulted for new allocations, changing the field has no effect on previously allocated
addresses.

{{site.prodname}} supports Kubernetes [annotations that force the use of specific IP addresses](../cni-plugin/configuration#requesting-a-specific-ip-address). These annotations take precedence over the `allowedUses` field.

#### IPIP

Routing of packets using IP-in-IP will be used when the destination IP address
is in an IP Pool that has IPIP enabled.  In addition, if the `ipipMode` is set to `CrossSubnet`,
{{site.prodname}} will only route using IP-in-IP if the IP address of the destination node is in a different
subnet. The subnet of each node is configured on the node resource (which may be automatically
determined when running the `{{site.nodecontainer}}` service).

For details on configuring IP-in-IP on your deployment, please refer to
[Configuring IP-in-IP]({{ site.baseurl }}/networking/vxlan-ipip).


> **Note**: Setting `natOutgoing` is recommended on any IP Pool with `ipip` enabled.
When `ipip` is enabled without `natOutgoing` routing between Workloads and
Hosts running {{site.prodname}} is asymmetric and may cause traffic to be filtered due to
[RPF](https://en.wikipedia.org/wiki/Reverse_path_forwarding){:target="_blank"} checks failing.
{: .alert .alert-info}

#### VXLAN

Routing of packets using VXLAN will be used when the destination IP address
is in an IP Pool that has VXLAN enabled.. In addition, if the `vxlanMode` is set to `CrossSubnet`,
{{site.prodname}} will only route using VXLAN if the IP address of the destination node is in a different
subnet. The subnet of each node is configured on the node resource (which may be automatically
determined when running the `{{site.nodecontainer}}` service).

> **Note**: Setting `natOutgoing` is recommended on any IP Pool with `vxlan` enabled.
When `vxlan` is enabled without `natOutgoing` routing between Workloads and
Hosts running {{site.prodname}} is asymmetric and may cause traffic to be filtered due to
[RPF](https://en.wikipedia.org/wiki/Reverse_path_forwarding){:target="_blank"} checks failing.
{: .alert .alert-info}

#### Block sizes

The default block sizes of `26` for IPv4 and `122` for IPv6 provide blocks of 64 addresses. This allows addresses to be allocated in groups to workloads running on the same host. By grouping addresses, fewer routes need to be exchanged between hosts and to other BGP peers. If a host allocates all of the addresses in a block then it will be allocated an additional block. If there are no more blocks available then the host can take addresses from blocks allocated to other hosts. Specific routes are added for the borrowed addresses which has an impact on route table size.

Increasing the block size from the default (e.g., using `24` for IPv4 to give 256 addresses per block) means fewer blocks per host, and potentially fewer routes. But try to ensure that there are at least as many blocks in the pool as there are hosts.

Reducing the block size from the default (e.g., using `28` for IPv4 to give 16 addresses per block) means more blocks per host and therefore potentially more routes. This can be beneficial if it allows the blocks to be more fairly distributed amongst the hosts.

#### Node Selector

For details on configuring IP pool node selectors, please read the
[Assign IP addresses based on topology guide.]({{ site.baseurl }}/networking/assign-ip-addresses-topology).

> **Tip**: To prevent an IP pool from being used automatically by {{site.prodname}} IPAM, while still allowing
> it to be used manually for static assignments, set the `IPPool`'s `nodeSelector` to `!all()`. Since the selector 
> matches no nodes, the IPPool will not be used automatically and, unlike setting `disabled: true`, it can still be
> used for manual assignments.
{: .alert .alert-success}

##### Selector reference

{% include content/selectors.md %}

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |

### See also

The [`IPReservation` resource](./ipreservation) allows for small parts of an IP pool to be reserved so that they will 
not be used for automatic IPAM assignments.
