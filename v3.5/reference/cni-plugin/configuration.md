---
title: Configuring the Calico CNI plugins
canonical_url: 'https://docs.projectcalico.org/v3.4/reference/cni-plugin/configuration'
---

The Calico CNI plugin is configured through the standard CNI
[configuration mechanism](https://github.com/containernetworking/cni/blob/master/SPEC.md#network-configuration)

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

The Calico CNI plugin supports the following datastore types:

* etcdv3 (default)
* kubernetes

### etcd location

The following options are valid when `datastore_type` is `etcdv3`.

Configure access to your etcd cluster using the following options.

| Option name         | Default | Description
|---------------------|---------|-------------
| `etcd_endpoints`    | None    | Comma-separated list of endpoints. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379` | string
| `etcd_key_file`     | None    | Path to the file containing the private key matching the CNI plugin's client certificate. Enables the CNI plugin to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calico-cni/key.pem` (optional) | string
| `etcd_cert_file`    | None    | Path to the file containing the client certificate issued to the CNI plugin. Enables the CNI plugin to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calico-cni/cert.pem` (optional) | string
| `etcd_ca_cert_file` | None    | Path to the file containing the root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures the CNI plugin to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing the CNI plugin to trust each of the CAs included. | string

The following options are deprecated.

* `etcd_authority` (default is `127.0.0.1:2379`)
  * If `etcd_authority` is set at the same time as `etcd_endpoints` then `etcd_endpoints` is used.
* `etcd_scheme` (default is `http`)

### Logging

* Logging is always to `stderr`
* Logging level can be controlled by setting `"log_level"` in the netconf. Allowed levels are
  * `ERROR` - Only error logs are emitted.
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

When using {{site.prodname}} IPAM, the following flags determine what IP addresses should be assigned. NOTE: These flags are strings and not boolean values.

* `assign_ipv4` (default: `"true"`)
* `assign_ipv6` (default: `"false"`)

A specific IP address can be chosen by using [`CNI_ARGS`](https://github.com/appc/cni/blob/master/SPEC.md#parameters) and setting `IP` to the desired value.

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

As a convenience, the API location location can also be configured directly, e.g.

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

## IPAM

When using the CNI `host-local` IPAM plugin, a special value `usePodCidr` is allowed for the subnet field (either at the top-level, or in a "range").  This tells the plugin to determine the subnet to use from the Kubernetes API based on the Node.podCIDR field.  Calico does not use the `gateway` field of a range so that field is not required and it will be ignored if present.

> **Note**: `usePodCidr` can only be used as the value of the `subnet` field, it cannot be used in
> `rangeStart` or `rangeEnd` so those values are not useful if `subnet` is set to `usePodCidr`.
{: .alert .alert-info}

Calico supports the host-local IPAM plugin's `routes` field as follows:

* If there is no `routes` field, Calico will install a default `0.0.0.0/0`, and/or `::/0` route into the pod (depending on whether the pod has an IPv4 and/or IPv6 address).

* If there is a `routes` field then Calico will program *only* the routes in the routes field into the pod.  Since Calico implements a point-to-point link into the pod, the `gw` field is not required and it will be ignored if present.  All routes that Calico installs will have Calico's link-local IP as the next hop.

Calico CNI plugin configuration:

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
        "ranges": [
            [
                { "subnet": "usePodCidr" }
            ],
            [
                { "subnet": "2001:db8::/96" }
            ]
        ],
        "routes": [
            { "dst": "0.0.0.0/0" },
            { "dst": "2001:db8::/96" }
        ]
    }
}
```

When making use of the `usePodCidr` option, the {{site.prodname}} CNI plugin requires read-only Kubernetes API access to the `Nodes` resource.

### IPAM Manipulation with Kubernetes Annotations

#### Specifying IP pools on a per-namespace or per-pod basis

In addition to specifying IP pools in the CNI config as discussed above, {{site.prodname}} IPAM supports specifying IP pools per-namespace or per-pod using the following [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/).

- `cni.projectcalico.org/ipv4pools`: A list of configured IPv4 Pools from which to choose an address for the Pod.

   Example:

   ```yaml
   annotations:
      "cni.projectcalico.org/ipv4pools": "[\"default-ipv4-ippool\"]"
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

> **Note**: The {{site.prodname}} CNI plugin supports specifying an annotation per namespace.
> If both the namespace and the pod have this annotation, the pod information will be used.
> Otherwise, if only the namespace has the annotation the annotation of the namespace will
> be used for each pod in it.
{: .alert .alert-info}


#### Requesting a Specific IP address

You can also request a specific IP address through [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/) with {{site.prodname}} IPAM.
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

You can request a floating IP address for a pod through [Kubernetes annotations](https://kubernetes.io/docs/user-guide/annotations/) with {{site.prodname}}.

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
