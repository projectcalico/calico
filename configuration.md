# CNI Configuration

The Calico CNI plugin is configured through the standard CNI [configuration mechanism](https://github.com/appc/cni/blob/master/SPEC.md#network-configuration)

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
### Etcd location
Specify the location of your etcd cluster using either
* `etcd_authority` (default is `127.0.0.1:2379`)
* `etcd_endpoints` (no default. Format is comma separated list of etcd servers e.g. `http://1.2.3.4:2379,http://5.6.7.8:2379`

If both are set then `etcd_endpoints` is used.

### Logging
* Logging is always to `stderr`
* Additional logging can be enabled by setting `"debug"` to `true` in the netconf, e.g.
```json
{
    "name": "any_name",
    "type": "calico",
    "debug": true,
    "ipam": {
        "type": "calico-ipam"
    }
}
```

### IPAM
When using Calico IPAM, the following flags determine what IP addresses should be assigned.
* `assign_ipv4` (default `true`)
* `assign_ipv6` (default `false`)

A specific IP address can be chosen by using [`CNI_ARGS`](https://github.com/appc/cni/blob/master/SPEC.md#parameters) and setting `IP` to the desired value.

When using the CNI `host-local` IPAM plugin, a special value `usePodCidr` is allowed for the subnet field.  This tells the plugin to determine the subnet to use from the Kubernetes API based on the Node.podCIDR field.  This is currently only supported when using `kubeconfig` for accessing the API. 

## Kubernetes specific

When using the Calico CNI plugin with Kubernetes, two additional config blocks can be specified to control how network policy is configured.

### Type
The type specifies which policy scheme to use.

* `k8s` uses the Kubernetes NetworkPolicy API in conjunction with the `calico/kube-policy-controller`.
* [`k8s-annotations`](https://github.com/projectcalico/calico-containers/blob/v0.20.0/docs/cni/kubernetes/AnnotationPolicy.md) is deprecated and uses annotations on pods to specify network policy.

To specify a policy, add the following block to the CNI network config:

```json
"policy": {
  "type": "<type>"
}
```

### Kubernetes API access details
When using either policy type, the CNI plugin needs to be told how to access the Kubernetes API server in the `policy` section of the network config.
* `k8s_api_root` (default `http://127.0.0.1:8080`)

The CNI plugin may need to authenticate with the Kubernetes API server. The following methods are supported in the `policy` section of the CNI network config, none of which have default values.
* `k8s_username`
* `k8s_password`
* `k8s_auth_token`
* `k8s_client_certificate`
* `k8s_client_key`
* `k8s_certificate_authority`
	* Verifying the API certificate against a CA only works if connecting to the API server using a hostname.

The following methods are supported in the `kubernetes` section of the CNI network config.
* `kubeconfig`
	* Path to a Kubernetes `kubeconfig` file.
* `node_name`
    * The node name to use when looking up the `usePodCidr` value (defaults to current hostname)

```json
"kubernetes": {
    "kubeconfig": "/path/to/kubeconfig"
}
```


[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-cni/configuration.md?pixel)](https://github.com/igrigorik/ga-beacon)
