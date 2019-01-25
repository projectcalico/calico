---
title: Configuring the Calico CNI plugins
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/cni-plugin/configuration'
---

The Calico CNI plugin is configured through the standard CNI [configuration mechanism](https://github.com/containernetworking/cni/blob/master/SPEC.md#network-configuration)

A minimal configuration file that uses Calico for networking and IPAM looks like this

```json
{
    "name": "any_name",
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
* kubernetes (experimental)

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
    "type": "calico",
    "log_level": "DEBUG",
    "ipam": {
        "type": "calico-ipam"
    }
}
```

### IPAM

When using Calico IPAM, the following flags determine what IP addresses should be assigned. NOTE: These flags are strings and not boolean values.

* `assign_ipv4` (default `"true"`)
* `assign_ipv6` (default `"false"`)

A specific IP address can be chosen by using [`CNI_ARGS`](https://github.com/appc/cni/blob/master/SPEC.md#parameters) and setting `IP` to the desired value.

## Kubernetes specific

When using the Calico CNI plugin with Kubernetes, the plugin must be able to access the Kubernetes API server in order to find the labels assigned to the Kubernetes pods. The recommended way to configure access is through a `kubeconfig` file specified in the `kubernetes` section of the network config. e.g.

```json
{
    "name": "any_name",
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

If you wish to use the Kubernetes NetworkPolicy API then you must set a policy type in the network config.
There is a single supported policy type, `k8s` which uses the Kubernetes NetworkPolicy API in conjunction with the `calico/kube-policy-controller`.

```json
{
    "name": "any_name",
    "type": "calico",
    "policy": {
      "type": "k8s",
      "k8s_api_root": "http://127.0.0.1:8080"
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
