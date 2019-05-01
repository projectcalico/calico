---
title: Configuring the Calico CNI plugins
canonical_url: 'https://docs.projectcalico.org/v3.7/reference/cni-plugin/configuration'
---

The Calico CNI plugin is configured through the standard CNI [configuration mechanism](https://github.com/containernetworking/cni/blob/master/SPEC.md#network-configuration)

A minimal configuration file that uses Calico for networking and IPAM looks like this

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

If the `calico-node` container on a node registered with a `NODENAME` other than the node hostname, the CNI plugin on this node must be configured with the same `nodename`:

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

The following option allows configuration of the Calico datastore type.

* `datastore_type` (default: etcdv2)

The Calico CNI plugin supports the following datastore types:

* etcdv2 (default)
* kubernetes

### Etcd location

The following options are valid when `datastore_type` is `etcdv2`.

Configure access to your etcd cluster using the following options

* `etcd_endpoints` (no default. Format is comma separated list of etcd servers e.g. `http://1.2.3.4:2379,http://5.6.7.8:2379`)
* `etcd_key_file` (no default. Format is an absolute path to a file)
* `etcd_cert_file` (no default. Format is an absolute path to a file)
* `etcd_ca_cert_file` (no default. Format is an absolute path to a file)

The following deprecated options are also supported

* `etcd_authority` (default is `127.0.0.1:2379`)
  * If `etcd_authority` is set at the same time as `etcd_endpoints` then `etcd_endpoints` is used.
* `etcd_scheme` (default is `http`)

### Logging

* Logging is always to `stderr`
* Logging level can be controlled by setting `"log_level"` in the netconf. Allowed levels are
  * `WARNING` - the default.
  * `INFO` - Enables some additional logging from the CNI plugin.
  * `DEBUG` - Enables lots of debug logging from both the CNI plugin and the underlying libcalico library.

```json
{
    "name": "any_name",
    "cniVersion": "0.1.0",
    "type": "calico",
    "log_level": "DEBUG",
    "ipam": {
        "type": "calico-ipam"
    }
}
```

### IPAM

When using Calico IPAM, the following flags determine what IP addresses should be assigned. NOTE: These flags are strings and not boolean values.

* `assign_ipv4` (default: `"true"`)
* `assign_ipv6` (default: `"false"`)

A specific IP address can be chosen by using [`CNI_ARGS`](https://github.com/appc/cni/blob/master/SPEC.md#parameters) and setting `IP` to the desired value.

By default, Calico IPAM will assign IP addresses from all the available IP pools.

Optionally, the list of possible IPv4 and IPv6 pools can also be specified via the following properties:

* `ipv4_pools`: An array of CIDR strings (e.g. `"ipv4_pools": ["10.0.0.0/24", "20.0.0.0/16"]`)
* `ipv6_pools`: An array of CIDR strings (e.g. `"ipv6_pools": ["2001:db8::1/120"]`)

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
        "ipv4_pools": ["10.0.0.0/24", "20.0.0.0/16"],
        "ipv6_pools": ["2001:db8::1/120"]
    }
}
```

> **Note**: `ipv6_pools` will be respected only when `assign_ipv6` is set to `"true"`.
{: .alert .alert-info}

Any IP pools specified in the CNI config must have already been created. It is an error to specify IP pools in the config that do not exist.

## Kubernetes specific

When using the Calico CNI plugin with Kubernetes, the plugin must be able to access the Kubernetes API server in order to find the labels assigned to the Kubernetes pods. The recommended way to configure access is through a `kubeconfig` file specified in the `kubernetes` section of the network config. e.g.

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

### Enabling Kubernetes Policy

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

When using `type: k8s`, the Calico CNI plugin requires read-only Kubernetes API access to the `Pods` resource in all namespaces.

Previous versions of the plugin (`v1.3.1` and earlier) supported an alternative type called [`k8s-annotations`](https://github.com/projectcalico/calicoctl/blob/v0.20.0/docs/cni/kubernetes/AnnotationPolicy.md) This uses annotations on pods to specify network policy but is no longer supported.

### Deprecated ways of specifying Kubernetes API access details

From the examples above, you can see that the `k8s_api_root` can appear in either the `kubernetes` or `policy` configuration blocks.

* `k8s_api_root` (default `http://127.0.0.1:8080`)

In addition, the following methods are supported in the `policy` section of the CNI network config only. None of them have default values.

* `k8s_auth_token`
* `k8s_client_certificate`
* `k8s_client_key`
* `k8s_certificate_authority`

## IPAM

When using the CNI `host-local` IPAM plugin, a special value `usePodCidr` is allowed for the subnet field.  This tells the plugin to determine the subnet to use from the Kubernetes API based on the Node.podCIDR field.

* `node_name`
    * The node name to use when looking up the `usePodCidr` value (defaults to current hostname)

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
        "subnet": "usePodCidr"
    }
}
```

When making use of the `usePodCidr` option, the Calico CNI plugin requires read-only Kubernetes API access to the `Nodes` resource.

### IPAM Manipulation with Kubernetes Annotations

#### Specifying IP pools on a per-Pod basis

In addition to specifying IP pools in the CNI config as discussed above, Calico IPAM supports specifying IP pools per-Pod using the following [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/).

- `cni.projectcalico.org/ipv4pools`: A list of configured IPv4 Pools from which to choose an address for the Pod.

   Example:

   ```yaml
   annotations:
      "cni.projectcalico.org/ipv4pools": "[\"192.168.0.0/16\"]"
   ```

- `cni.projectcalico.org/ipv6pools`: A list of configured IPv6 Pools from which to choose an address for the Pod.

   Example:

   ```yaml
   annotations:
      "cni.projectcalico.org/ipv6pools": "[\"2001:db8::1/120\"]"
   ```

If provided, these IP pools will override any IP pools specified in the CNI config.


> **Note**: This requires the IP pools to exist before `ipv4pools` or
> `ipv6pools` annotations are used. Requesting a subset of an IP pool
> is not supported. IP pools requested in the annotations must exactly
> match a configured [IPPool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool) resource.
{: .alert .alert-info}


#### Requesting a Specific IP address

You can also request a specific IP address through [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/) with Calico IPAM.
There are two annotations to request a specific IP address:

- `cni.projectcalico.org/ipAddrs`: A list of IPv4 and/or IPv6 addresses to assign to the Pod. The requested IP addresses will be assigned from Calico IPAM and must exist within a configured IP pool.

  Example:

   ```yaml
   annotations:
        "cni.projectcalico.org/ipAddrs": "[\"192.168.0.1\"]"
   ```

- `cni.projectcalico.org/ipAddrsNoIpam`: A list of IPv4 and/or IPv6 addresses to assign to the Pod, bypassing IPAM. Any IP conflicts and routing have to be taken care of manually or by some other system.
Calico will only distribute routes to a Pod if its IP address falls within a Calico IP pool. If you assign an IP address that is not in a Calico IP pool, you must ensure that routing to that IP address is taken care of through another mechanism.

  Example:

   ```yaml
   annotations:
        "cni.projectcalico.org/ipAddrsNoIpam": "[\"10.0.0.1\"]"
   ```

> **Note**:
> - The `ipAddrs` and `ipAddrsNoIpam` annotations can't be used together.
> - You can only specify one IPv4/IPv6 or one IPv4 and one IPv6 address with these annotations.
> - When `ipAddrs` or `ipAddrsNoIpam` is used with `ipv4pools` or `ipv6pools`, `ipAddrs` / `ipAddrsNoIpam` take priority.
{: .alert .alert-info}
