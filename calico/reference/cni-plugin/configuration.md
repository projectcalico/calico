---
title: Configure the Calico CNI plugins
description: Details for configuring the Calico CNI plugins.  
canonical_url: '/reference/cni-plugin/configuration'
---

The {{site.prodname}} CNI plugin is configured through the standard CNI
[configuration mechanism](https://github.com/containernetworking/cni/blob/master/SPEC.md#network-configuration){:target="_blank"}

A minimal configuration file that uses {{site.prodname}} for networking
and IPAM looks like this

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
```

If the `{{site.nodecontainer}}` container on a node registered with a `NODENAME` other than the node hostname, the CNI plugin on this node must be configured with the same `nodename`:

```json
{
    "name": "any_name",
    "nodename": "<NODENAME>",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
```

Additional configuration can be added as detailed below.

## Generic

### Datastore type

The following option allows configuration of the {{site.prodname}} datastore type.

* `datastore_type` (default: etcdv3)

The {{site.prodname}} CNI plugin supports the following datastore types:

* etcdv3 (default)
* kubernetes

### etcd location

The following options are valid when `datastore_type` is `etcdv3`.

Configure access to your etcd cluster using the following options.

| Option name          | Default | Description
|----------------------|---------|-------------
| `etcd_endpoints`     | None    | Comma-separated list of endpoints. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379` | string
| `etcd_discovery_srv` | None    | Domain name to discover etcd endpoints via SRV records. Mutually exclusive with `etcdEndpoints`. Example: `example.com` (optional) | string
| `etcd_key_file`      | None    | Path to the file containing the private key matching the CNI plugin's client certificate. Enables the CNI plugin to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calico-cni/key.pem` (optional) | string
| `etcd_cert_file`     | None    | Path to the file containing the client certificate issued to the CNI plugin. Enables the CNI plugin to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calico-cni/cert.pem` (optional) | string
| `etcd_ca_cert_file`  | None    | Path to the file containing the root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures the CNI plugin to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing the CNI plugin to trust each of the CAs included. | string

The following options are deprecated.

* `etcd_authority` (default is `127.0.0.1:2379`)
  * If `etcd_authority` is set at the same time as `etcd_endpoints` then `etcd_endpoints` is used.
* `etcd_scheme` (default is `http`)

### Logging

Logging is always to `stderr`. Logs are also written to `/var/log/calico/cni/cni.log` on each host by default.

Logging can be configured using the following options in the netconf.

| Option name          | Default                       | Description
|----------------------|-------------------------------|-------------
| `log_level`          | INFO                          | Logging level. Allowed levels are `ERROR`, `WARNING`, `INFO`, and `DEBUG`.
| `log_file_path`      | `/var/log/calico/cni/cni.log` | Location on each host to write CNI log files to. Logging to file can be disabled by removing this option.
| `log_file_max_size`  | 100                           | Max file size in MB log files can reach before they are rotated.
| `log_file_max_age`   | 30                            | Max age in days that old log files will be kept on the host before they are removed.
| `log_file_max_count` | 10                            | Max number of rotated log files allowed on the host before they are cleaned up.

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "log_level": "DEBUG",
    "log_file_path": "/var/log/calico/cni/cni.log",
    "ipam": {
        "type": "calico-ipam"
    }
}
```

### IPAM

When using {{site.prodname}} IPAM, the following flags determine what IP addresses should be assigned. NOTE: These flags are strings and not boolean values.

* `assign_ipv4` (default: `"true"`)
* `assign_ipv6` (default: `"false"`)

A specific IP address can be chosen by using [`CNI_ARGS`](https://github.com/appc/cni/blob/master/SPEC.md#parameters){:target="_blank"} and setting `IP` to the desired value.

By default, {{site.prodname}} IPAM will assign IP addresses from all the available IP pools.

Optionally, the list of possible IPv4 and IPv6 pools can also be specified via the following properties:

* `ipv4_pools`: An array of CIDR strings or pool names. (e.g., `"ipv4_pools": ["10.0.0.0/24", "20.0.0.0/16", "default-ipv4-ippool"]`)
* `ipv6_pools`: An array of CIDR strings or pool names.  (e.g., `"ipv6_pools": ["2001:db8::1/120", "namedpool"]`)

Example CNI config:

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam",
        "assign_ipv4": "true",
        "assign_ipv6": "true",
        "ipv4_pools": ["10.0.0.0/24", "20.0.0.0/16", "default-ipv4-ippool"],
        "ipv6_pools": ["2001:db8::1/120", "default-ipv6-ippool"]
    }
}
```

> **Note**: `ipv6_pools` will be respected only when `assign_ipv6` is set to `"true"`.
{: .alert .alert-info}

Any IP pools specified in the CNI config must have already been created. It is an error to specify IP pools in the config that do not exist.

### Container settings

The following options allow configuration of settings within the container namespace.

* allow_ip_forwarding (default is `false`)

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    },
    "container_settings": {
        "allow_ip_forwarding": true
    }
}
```

### Readiness Gates

The following option makes CNI plugin wait for specified endpoint(s) to be ready before configuring pod networking.

* `readiness_gates`

This is an optional property that takes an array of URLs. Each URL specified will be polled for readiness and pod networking will continue startup once all readiness_gates are ready.

Example CNI config:

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    },
    "readiness_gates": ["http://localhost:9099/readiness", "http://localhost:8888/status"],
}
```

## Kubernetes specific

When using the {{site.prodname}} CNI plugin with Kubernetes, the plugin must be able to access the Kubernetes API server in order to find the labels assigned to the Kubernetes pods. The recommended way to configure access is through a `kubeconfig` file specified in the `kubernetes` section of the network config. e.g.

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "kubernetes": {
        "kubeconfig": "/path/to/kubeconfig"
    },
    "ipam": {
        "type": "calico-ipam"
    }
}
```

As a convenience, the API location can also be configured directly, e.g.

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "kubernetes": {
        "k8s_api_root": "http://127.0.0.1:8080"
    },
    "ipam": {
        "type": "calico-ipam"
    }
}
```

### Enabling Kubernetes policy

If you wish to use the Kubernetes `NetworkPolicy` resource then you must set a policy type in the network config.
There is a single supported policy type, `k8s`. When set,
you must also run calico/kube-controllers with the policy, profile, and workloadendpoint controllers enabled.

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "policy": {
      "type": "k8s"
    },
    "kubernetes": {
        "kubeconfig": "/path/to/kubeconfig"
    },
    "ipam": {
        "type": "calico-ipam"
    }
}
```

When using `type: k8s`, the {{site.prodname}} CNI plugin requires read-only Kubernetes API access to the `Pods` resource in all namespaces.

## IPAM

### Using host-local IPAM

Calico can be configured to use [host-local IPAM](https://www.cni.dev/plugins/current/ipam/host-local/) instead of the default `calico-ipam`. Host
local IPAM uses a pre-determined CIDR per-host, and stores allocations locally on each node. This is in contrast to Calico IPAM, which dynamically
allocates blocks of addresses and single addresses alike in response to cluster needs. 

Host local IPAM is generally only used on clusters where integration with the Kubernetes [route controller](https://kubernetes.io/docs/concepts/architecture/cloud-controller/#route-controller) is necessary. 
Note that some Calico features - such as the ability to request a specific address or pool for a pod - require Calico IPAM in order to function, and will not work with host-local IPAM enabled.

{% tabs %}
  <label:Operator,active:true>
<%

The `host-local` IPAM plugin can be configured by setting the `Spec.CNI.IPAM.Plugin` field to `HostLocal` on the [operator.tigera.io/Installation]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.Installation) API.

Calico will use the `host-local` IPAM plugin to allocate IPv4 addresses from the node's IPv4 pod CIDR if there is an IPv4 pool configured in `Spec.IPPools`, and an IPv6 address from the node's IPv6 pod CIDR if
there is an IPv6 pool configured in `Spec.IPPools`.

The following example configures Calico to assign dual-stack IPs to pods using the host-local IPAM plugin.

```yaml
kind: Installation
apiVersion: operator.tigera.io/v1
metadata:
  name: default
spec:
  calicoNetwork:
    ipPools:
    - cidr: 192.168.0.0/16
    - cidr: 2001:db8::/64
  cni:
    type: Calico
    ipam:
      type: HostLocal
```

%>
  <label:Manifest>
<%

When using the CNI `host-local` IPAM plugin, two special values - `usePodCidr` and `usePodCidrIPv6` - are allowed for the subnet field (either at the top-level, or in a "range").  This tells the plugin to determine the subnet to use from the Kubernetes API based on the Node.podCIDR field. {{site.prodname}} does not use the `gateway` field of a range so that field is not required and it will be ignored if present.

> **Note**: `usePodCidr` and `usePodCidrIPv6` can only be used as the value of the `subnet` field, it cannot be used in
> `rangeStart` or `rangeEnd` so those values are not useful if `subnet` is set to `usePodCidr`.
{: .alert .alert-info}

{{site.prodname}} supports the host-local IPAM plugin's `routes` field as follows:

* If there is no `routes` field, {{site.prodname}} will install a default `0.0.0.0/0`, and/or `::/0` route into the pod (depending on whether the pod has an IPv4 and/or IPv6 address).
* If there is a `routes` field then {{site.prodname}} will program *only* the routes in the routes field into the pod.  Since {{site.prodname}} implements a point-to-point link into the pod, the `gw` field is not required and it will be ignored if present.  All routes that {{site.prodname}} installs will have {{site.prodname}}'s link-local IP as the next hop.

{{site.prodname}} CNI plugin configuration:

* `node_name`
    * The node name to use when looking up the CIDR value (defaults to current hostname)

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "kubernetes": {
        "kubeconfig": "/path/to/kubeconfig",
        "node_name": "node-name-in-k8s"
    },
    "ipam": {
        "type": "host-local",
        "ranges": [
            [
                { "subnet": "usePodCidr" }
            ],
            [
                { "subnet": "usePodCidrIPv6" }
            ]
        ],
        "routes": [
            { "dst": "0.0.0.0/0" },
            { "dst": "2001:db8::/96" }
        ]
    }
}
```

When making use of the `usePodCidr` or `usePodCidrIPv6` options, the {{site.prodname}} CNI plugin requires read-only Kubernetes API access to the `Nodes` resource.

#### Configuring node and typha

When using `host-local` IPAM with the Kubernetes API datastore, you must configure both {{site.nodecontainer}} and the Typha deployemt to use the `Node.podCIDR` field by setting the environment variable `USE_POD_CIDR=true` in each.

%>
{% endtabs %}

### Using Kubernetes annotations

#### Specifying IP pools on a per-namespace or per-pod basis

In addition to specifying IP pools in the CNI config as discussed above, {{site.prodname}} IPAM supports specifying IP pools per-namespace or per-pod using the following [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/){:target="_blank"}.

- `cni.projectcalico.org/ipv4pools`: A list of configured IPv4 Pools from which to choose an address for the pod.

   Example:

   ```yaml
   annotations:
      "cni.projectcalico.org/ipv4pools": "[\"default-ipv4-ippool\"]"
   ```

- `cni.projectcalico.org/ipv6pools`: A list of configured IPv6 Pools from which to choose an address for the pod.

   Example:

   ```yaml
   annotations:
      "cni.projectcalico.org/ipv6pools": "[\"2001:db8::1/120\"]"
   ```

If provided, these IP pools will override any IP pools specified in the CNI config.

> **Note**: This requires the IP pools to exist before `ipv4pools` or
> `ipv6pools` annotations are used. Requesting a subset of an IP pool
> is not supported. IP pools requested in the annotations must exactly
> match a configured [IPPool]({{ site.baseurl }}/reference/resources/ippool) resource.
{: .alert .alert-info}

> **Note**: The {{site.prodname}} CNI plugin supports specifying an annotation per namespace.
> If both the namespace and the pod have this annotation, the pod information will be used.
> Otherwise, if only the namespace has the annotation the annotation of the namespace will
> be used for each pod in it.
{: .alert .alert-info}

#### Requesting a specific IP address

You can also request a specific IP address through [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/){:target="_blank"} with {{site.prodname}} IPAM.
There are two annotations to request a specific IP address:

- `cni.projectcalico.org/ipAddrs`: A list of IPv4 and/or IPv6 addresses to assign to the Pod. The requested IP addresses will be assigned from {{site.prodname}} IPAM and must exist within a configured IP pool.

  Example:

   ```yaml
   annotations:
        "cni.projectcalico.org/ipAddrs": "[\"192.168.0.1\"]"
   ```

- `cni.projectcalico.org/ipAddrsNoIpam`: A list of IPv4 and/or IPv6 addresses to assign to the Pod, bypassing IPAM. Any IP conflicts and routing have to be taken care of manually or by some other system.
{{site.prodname}} will only distribute routes to a Pod if its IP address falls within a {{site.prodname}} IP pool. If you assign an IP address that is not in a {{site.prodname}} IP pool, you must ensure that routing to that IP address is taken care of through another mechanism.

  Example:

   ```yaml
   annotations:
        "cni.projectcalico.org/ipAddrsNoIpam": "[\"10.0.0.1\"]"
   ```

   The ipAddrsNoIpam feature is disabled by default. It can be enabled in the feature_control section of the CNI network config:

   ```json
   {
        "name": "any_name",
        "cniVersion": "0.1.0",
        "type": "calico",
        "ipam": {
            "type": "calico-ipam"
        },
       "feature_control": {
           "ip_addrs_no_ipam": true
       }
   }
   ```

   > **Warning**: This feature allows for the bypassing of network policy via IP spoofing.
   > Users should make sure the proper admission control is in place to prevent users from selecting arbitrary IP addresses.
   {: .alert .alert-danger}

> **Note**:
> - The `ipAddrs` and `ipAddrsNoIpam` annotations can't be used together.
> - You can only specify one IPv4/IPv6 or one IPv4 and one IPv6 address with these annotations.
> - When `ipAddrs` or `ipAddrsNoIpam` is used with `ipv4pools` or `ipv6pools`, `ipAddrs` / `ipAddrsNoIpam` take priority.
{: .alert .alert-info}

#### Requesting a floating IP

You can request a floating IP address for a pod through [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/){:target="_blank"} with {{site.prodname}}.

> **Note**:
> The specified address must belong to an IP Pool for advertisement to work properly.
{: .alert .alert-info}

- `cni.projectcalico.org/floatingIPs`: A list of floating IPs which will be assigned to the pod's workload endpoint.

  Example:

   ```yaml
   annotations:
        "cni.projectcalico.org/floatingIPs": "[\"10.0.0.1\"]"
   ```

   The floatingIPs feature is disabled by default. It can be enabled in the feature_control section of the CNI network config:

   ```json
   {
        "name": "any_name",
        "cniVersion": "0.1.0",
        "type": "calico",
        "ipam": {
            "type": "calico-ipam"
        },
       "feature_control": {
           "floating_ips": true
       }
   }
   ```

   > **Warning**: This feature can allow pods to receive traffic which may not have been intended for that pod.
   > Users should make sure the proper admission control is in place to prevent users from selecting arbitrary floating IP addresses.
   {: .alert .alert-danger}

### Using IP pools node selectors

Nodes will only assign workload addresses from IP pools which select them. By
default, IP pools select all nodes, but this can be configured using the
`nodeSelector` field. Check out the [IP pool resource
document]({{ site.baseurl }}/reference/resources/ippool)
for more details.

Example:

1. Create (or update) an IP pool that only allocates IPs for nodes where it
   contains a label `rack=0`.

   ```bash
   calicoctl create -f -<<EOF
   apiVersion: projectcalico.org/v3
   kind: IPPool
   metadata:
      name: rack-0-ippool
   spec:
      cidr: 192.168.0.0/24
      ipipMode: Always
      natOutgoing: true
      nodeSelector: rack == "0"
   EOF
   ```

2. Label a node with `rack=0`.

   ```bash
   kubectl label nodes kube-node-0 rack=0
   ```

Check out the usage guide on [assign IP addresses based on
topology]({{ site.baseurl }}/networking/assign-ip-addresses-topology)
for a full example.

### CNI network configuration lists

The CNI 0.3.0 [spec](https://github.com/containernetworking/cni/blob/spec-v0.3.0/SPEC.md#network-configuration-lists){:target="_blank"} supports "chaining" multiple CNI plugins together. {{site.prodname}} supports the following Kubernetes CNI plugins, which are enabled by default. Although chaining other CNI plugins may work, we support only the following tested CNI plugins. 

**Port mapping plugin**

{{site.prodname}} is required to implement Kubernetes host port functionality and is enabled by default. 

> **Note**: Be aware of the following {% include open-new-window.html text='portmap plugin CNI issue' url='https://github.com/containernetworking/cni/issues/605' %} where draining nodes
> may take a long time with a cluster of 100+ nodes and 4000+ services.
{: .alert .alert-info}

To disable it, remove the portmap section from the CNI network configuration in the {{site.prodname}} manifests. 

```json
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
```
{: .no-select-button}

**Traffic shaping plugin**

The {% include open-new-window.html text='traffic shaping Kubernetes CNI plugin' url='https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/' %} supports pod ingress and egress traffic shaping. This bandwidth management technique delays the flow of certain types of network packets to ensure network performance for higher priority applications. It is enabled by default. 

You can add the `kubernetes.io/ingress-bandwidth` and `kubernetes.io/egress-bandwidth` annotations to your pod. For example, the following sets a 1 megabit-per-second connection for ingress and egress traffic.

```bash
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubernetes.io/ingress-bandwidth: 1M
    kubernetes.io/egress-bandwidth: 1M
...
```
To disable it, remove the bandwidth section from the the CNI network configuration in the {{site.prodname}} manifests.

```json
        { 
          "type": "bandwidth",
          "capabilities": {"bandwidth": true}
        }
```   
{: .no-select-button}     

### Order of precedence

If more than one of these methods are used for IP address assignment, they will
take on the following precedence, 1 being the highest:

1. Kubernetes annotations
2. CNI configuration
3. IP pool node selectors

> **Note**: {{site.prodname}} IPAM will not reassign IP addresses to workloads
> that are already running. To update running workloads with IP addresses from
> a newly configured IP pool, they must be recreated. We recommmend doing this
> before going into production or during a maintenance window.
{: .alert .alert-info}

### Specify num_queues for veth interfaces

`num_rx_queues` and `num_tx_queues` can be set using the `num_queues` option in the CNI configuration. Default: 1

For example:

```json
{
  "num_queues": 3,
}
```
