---
title: Configuring calico/node
description: Customize calico/node using environment variables.
canonical_url: '/reference/node/configuration'
---

The `{{site.nodecontainer}}` container is deployed to every node (on Kubernetes, by a DaemonSet), and runs three internal daemons:

* Felix, the Calico daemon that runs on every node and provides endpoints.
* BIRD, the BGP daemon that distributes routing information to other nodes.
* confd, a daemon that watches the Calico datastore for config changes and updates BIRD’s config files.

For manifest-based installations, `{{site.nodecontainer}}` is primarily configured through environment
variables, typically set in the deployment manifest. Individual nodes may also be updated through the Node
custom resource. `{{site.nodecontainer}}` can also be configured through the Calico Operator.

The rest of this page lists the available configuration options, and is followed by specific considerations for
various settings.

{% tabs %}
  <label:Operator,active:true>
<%

calico/node does not need to be configured directly when installed by the operator. For a complete operator 
configuration reference, see [the installation API reference documentation][installation].

  <label:Manifest>
<%

## Environment variables

### Configuring the default IP pool(s)

Calico uses IP pools to configure how addresses are allocated to pods, and how networking works for certain
sets of addresses. You can see the full schema for IP pools here.

`{{site.nodecontainer}}` can be configured to create a default IP pool for you, but only if none already
exist in the cluster. The following options control the parameters on the created pool.

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| CALICO_IPV4POOL_CIDR | The IPv4 Pool to create if none exists at start up. It is invalid to define this variable and NO_DEFAULT_POOLS. [Default: First not used in locally of (192.168.0.0/16, 172.16.0.0/16, .., 172.31.0.0/16) ] | IPv4 CIDR |
| CALICO_IPV4POOL_BLOCK_SIZE | Block size to use for the IPv4 Pool created at startup.  Block size for IPv4 should be in the range 20-32 (inclusive) [Default: `26`] | int |
| CALICO_IPV4POOL_IPIP | IPIP Mode to use for the IPv4 Pool created at start up. If set to a value other than `Never`, `CALICO_IPV4POOL_VXLAN` should not be set. [Default: `Always`] | Always, CrossSubnet, Never ("Off" is also accepted as a synonym for "Never") |
| CALICO_IPV4POOL_VXLAN | VXLAN Mode to use for the IPv4 Pool created at start up.  If set to a value other than `Never`, `CALICO_IPV4POOL_IPIP` should not be set. [Default: `Never`] | Always, CrossSubnet, Never |
| CALICO_IPV4POOL_NAT_OUTGOING | Controls NAT Outgoing for the IPv4 Pool created at start up. [Default: `true`] | boolean |
| CALICO_IPV4POOL_NODE_SELECTOR | Controls the NodeSelector for the IPv4 Pool created at start up. [Default: `all()`] | [selector]({{site.baseurl}}/reference/resources/ippool#node-selector) |
| CALICO_IPV6POOL_CIDR | The IPv6 Pool to create if none exists at start up. It is invalid to define this variable and NO_DEFAULT_POOLS. [Default: `<a randomly chosen /48 ULA>`] | IPv6 CIDR |
| CALICO_IPV6POOL_BLOCK_SIZE | Block size to use for the IPv6 POOL created at startup.  Block size for IPv6 should be in the range 116-128 (inclusive) [Default: `122`] | int |
| CALICO_IPV6POOL_VXLAN | VXLAN Mode to use for the IPv6 Pool created at start up. [Default: `Never`] | Always, CrossSubnet, Never |
| CALICO_IPV6POOL_NAT_OUTGOING | Controls NAT Outgoing for the IPv6 Pool created at start up. [Default: `false`] | boolean |
| CALICO_IPV6POOL_NODE_SELECTOR | Controls the NodeSelector for the IPv6 Pool created at start up. [Default: `all()`] | [selector]({{site.baseurl}}/reference/resources/ippool#node-selector) |
| NO_DEFAULT_POOLS | Prevents  {{site.prodname}} from creating a default pool if one does not exist. [Default: `false`] | boolean |

### Configuring BGP Networking

BGP configuration for Calico nodes is normally configured through the [Node]({{site.baseurl}}/reference/resources/node), [BGPConfiguration]({{site.baseurl}}/reference/resources/bgpconfig), and [BGPPeer]({{site.baseurl}}/reference/resources/bgppeer) resources.
`{{site.nodecontainer}}` also exposes some options to allow setting certain fields on these objects, as described
below.

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| NODENAME | A unique identifier for this host.  See [node name determination](#node-name-determination) for more details. | lowercase string |
| IP | The IPv4 address to assign this host or detection behavior at startup. Refer to [IP setting](#ip-setting) for the details of the behavior possible with this field. | IPv4 |
| IP6 | The IPv6 address to assign this host or detection behavior at startup. Refer to [IP setting](#ip-setting) for the details of the behavior possible with this field. | IPv6 |
| IP_AUTODETECTION_METHOD | The method to use to autodetect the IPv4 address for this host. This is only used when the IPv4 address is being autodetected. See [IP Autodetection methods](#ip-autodetection-methods) for details of the valid methods. [Default: `first-found`] | string |
| IP6_AUTODETECTION_METHOD | The method to use to autodetect the IPv6 address for this host. This is only used when the IPv6 address is being autodetected. See [IP Autodetection methods](#ip-autodetection-methods) for details of the valid methods. [Default: `first-found`] | string |
| AS | The AS number for this node. When specified, the value is saved in the node resource configuration for this host, overriding any previously configured value. When omitted, if an AS number has been previously configured in the node resource, that AS number is used for the peering.  When omitted, if an AS number has not yet been configured in the node resource, the node will use the global value (see [example modifying Global BGP settings]({{site.baseurl}}/networking/bgp) for details.) | int |
| CALICO_ROUTER_ID | Sets the `router id` to use for BGP if no IPv4 address is set on the node. For an IPv6-only system, this may be set to `hash`. It then uses the hash of the nodename to create a 4 byte router id. See note below. [Default: ``] | string |
| CALICO_K8S_NODE_REF | The name of the corresponding node object in the Kubernetes API. When set, used for correlating this node with events from the Kubernetes API. | string |

### Configuring Datastore Access

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| DATASTORE_TYPE | Type of datastore. [Default: `kubernetes`] | kubernetes, etcdv3 |

#### Configuring Kubernetes Datastore Access

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| KUBECONFIG | When using the Kubernetes datastore, the location of a kubeconfig file to use. | string |
| K8S_API_ENDPOINT | Location of the Kubernetes API.  Not required if using kubeconfig.       | string |
| K8S_CERT_FILE | Location of a client certificate for accessing the Kubernetes API.          | string |
| K8S_KEY_FILE | Location of a client key for accessing the Kubernetes API.                   | string |
| K8S_CA_FILE | Location of a CA for accessing the Kubernetes API.                            | string |

> **Note**: When {{site.prodname}} is configured to use the Kubernetes API as the datastore, the environments
> used for BGP configuration are ignored—this includes selection of the node AS number (AS)
> and all of the IP selection options (IP, IP6, IP_AUTODETECTION_METHOD, IP6_AUTODETECTION_METHOD).
>
{: .alert .alert-info}

#### Configuring etcd Datastore Access

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| ETCD_ENDPOINTS     | A comma separated list of etcd endpoints [Example: `http://127.0.0.1:2379,http://127.0.0.2:2379`] (required) | string |
| ETCD_DISCOVERY_SRV | Domain name to discover etcd endpoints via SRV records. Mutually exclusive with `ETCD_ENDPOINTS`. [Example: `example.com`] (optional) | string |
| ETCD_KEY_FILE      | Path to the file containing the private key matching the `{{site.nodecontainer}}` client certificate. Enables `{{site.nodecontainer}}` to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/node/key.pem` (optional) | string |
| ETCD_CERT_FILE     | Path to the file containing the client certificate issued to `{{site.nodecontainer}}`. Enables `{{site.nodecontainer}}` to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/node/cert.pem` (optional) | string |
| ETCD_CA_CERT_FILE  | Path to the file containing the root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures `{{site.nodecontainer}}` to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing `{{site.nodecontainer}}` to trust each of the CAs included. Example: `/etc/node/ca.pem` | string |

### Configuring Logging

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| CALICO_DISABLE_FILE_LOGGING | Disables logging to file. [Default: "false"] | string |
| CALICO_STARTUP_LOGLEVEL      | The log severity above which startup `{{site.nodecontainer}}` logs are sent to the stdout. [Default: `ERROR`] | DEBUG, INFO, WARNING, ERROR, CRITICAL, or NONE (case-insensitive) |

### Configuring CNI Plugin

`{{site.nodecontainer}}` has a few options that are configurable based on the CNI plugin and CNI plugin
configuration used on the cluster.

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| USE_POD_CIDR | Use the Kubernetes `Node.Spec.PodCIDR` field when using host-local IPAM. Requires Kubernetes API datastore. This field is required when using the Kubernetes API datastore with host-local IPAM. [Default: false] | boolean |
| CALICO_MANAGE_CNI | Tells Calico to update the kubeconfig file at /host/etc/cni/net.d/calico-kubeconfig on credentials change. [Default: true] | boolean |

### Other Environment Variables

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| DISABLE_NODE_IP_CHECK | Skips checks for duplicate Node IPs. This can reduce the load on the cluster when a large number of Nodes are restarting. [Default: `false`] | boolean |
| WAIT_FOR_DATASTORE | Wait for connection to datastore before starting. If a successful connection is not made, node will shutdown. [Default: `false`] | boolean |
| CALICO_NETWORKING_BACKEND | The networking backend to use.  In `bird` mode, Calico will provide BGP networking using the BIRD BGP daemon; VXLAN networking can also be used.  In `vxlan` mode, only VXLAN networking is provided; BIRD and BGP are disabled.  If set to `none` (also known as policy-only mode), both BIRD and VXLAN are disabled. [Default: `bird`] | bird, vxlan, none |
| CLUSTER_TYPE | Contains comma delimited list of indicators about this cluster.  e.g. k8s, mesos, kubeadm, canal, bgp | string |

## Appendix

### Node name determination

The `{{site.nodecontainer}}` must know the name of the node on which it is running. The node name is used to
retrieve the [Node resource]({{site.baseurl}}/reference/resources/node) configured for this node if it exists, or to create a new node resource representing the node if it does not. It is
also used to associate the node with per-node [BGP configuration]({{site.baseurl}}/reference/resources/bgpconfig), [felix configuration]({{site.baseurl}}/reference/resources/felixconfig), and endpoints.

When launched, the `{{site.nodecontainer}}` container sets the node name according to the following order of precedence:

1. The value specified in the `NODENAME` environment variable, if set.
1. The value specified in `/var/lib/calico/nodename`, if it exists.
1. The value specified in the `HOSTNAME` environment variable, if set.
1. The hostname as returned by the operating system, converted to lowercase.

Once the node has determined its name, the value will be cached in `/var/lib/calico/nodename` for future use.

For example, if given the following conditions:

- `NODENAME=""`
- `/var/lib/calico/nodename` does not exist
- `HOSTNAME="host-A"`
- The operating system returns "host-A.internal.myorg.com" for the hostname

{{site.nodecontainer}} will use "host-a" for its name and will write the value in `/var/lib/calico/nodename`. If {{site.nodecontainer}}
is then restarted, it will use the cached value of "host-a" read from the file on disk.

### IP setting

The IP (for IPv4) and IP6 (for IPv6) environment variables are used to set,
force autodetection, or disable auto detection of the address for the
appropriate IP version for the node. When the environment variable is set,
the address is saved in the
[node resource configuration]({{ site.baseurl }}/reference/resources/node)
for this host, overriding any previously configured value.

calico/node will attempt to detect subnet information from the host, and augment the provided address
if possible.

#### IP setting special case values

There are several special case values that can be set in the IP(6) environment variables, they are:

- Not set or empty string: Any previously set address on the node
  resource will be used. If no previous address is set on the node resource
  the two versions behave differently:
  - IP will do autodetection of the IPv4 address and set it on the node
    resource.
  - IP6 will not do autodetection.
- `autodetect`: Autodetection will always be performed for the IP address and
  the detected address will overwrite any value configured in the node
  resource.
- `none`: Autodetection will not be performed (this is useful to disable IPv4).

### IP autodetection methods

When {{site.prodname}} is used for routing, each node must be configured with an IPv4
address and/or an IPv6 address that will be used to route between
nodes. To eliminate node specific IP address configuration, the `{{site.nodecontainer}}`
container can be configured to autodetect these IP addresses. In many systems,
there might be multiple physical interfaces on a host, or possibly multiple IP
addresses configured on a physical interface. In these cases, there are
multiple addresses to choose from and so autodetection of the correct address
can be tricky.

The IP autodetection methods are provided to improve the selection of the
correct address, by limiting the selection based on suitable criteria for your
deployment.

The following sections describe the available IP autodetection methods.

#### first-found

The `first-found` option enumerates all interface IP addresses and returns the
first valid IP address (based on IP version and type of address) on
the first valid interface.  Certain known "local" interfaces
are omitted, such  as the docker bridge.  The order that both the interfaces
and the IP addresses are listed is system dependent.

This is the default detection method. However, since this method only makes a
very simplified guess, it is recommended to either configure the node with a
specific IP address, or to use one of the other detection methods.

e.g.

```
IP_AUTODETECTION_METHOD=first-found
IP6_AUTODETECTION_METHOD=first-found
```

#### kubernetes-internal-ip

The `kubernetes-internal-ip` method will select the first internal IP address listed in the Kubernetes node's `Status.Addresses` field

Example:

```
IP_AUTODETECTION_METHOD=kubernetes-internal-ip
IP6_AUTODETECTION_METHOD=kubernetes-internal-ip
```

#### can-reach=DESTINATION

The `can-reach` method uses your local routing to determine which IP address
will be used to reach the supplied destination.  Both IP addresses and domain
names may be used.

Example using IP addresses:

```
IP_AUTODETECTION_METHOD=can-reach=8.8.8.8
IP6_AUTODETECTION_METHOD=can-reach=2001:4860:4860::8888
```

Example using domain names:

```
IP_AUTODETECTION_METHOD=can-reach=www.google.com
IP6_AUTODETECTION_METHOD=can-reach=www.google.com
```

#### interface=INTERFACE-REGEX

The `interface` method uses the supplied interface [regular expression](https://pkg.go.dev/regexp){:target="_blank"}
to enumerate matching interfaces and to return the first IP address on
the first matching interface.  The order that both the interfaces
and the IP addresses are listed is system dependent.

Example with valid IP address on interface eth0, eth1, eth2 etc.:

```
IP_AUTODETECTION_METHOD=interface=eth.*
IP6_AUTODETECTION_METHOD=interface=eth.*
```


#### skip-interface=INTERFACE-REGEX

The `skip-interface` method uses the supplied interface [regular expression](https://pkg.go.dev/regexp){:target="_blank"}
to exclude interfaces and to return the first IP address on the first
interface that does not match. The order that both the interfaces
and the IP addresses are listed is system dependent.

Example with valid IP address on interface exclude enp6s0f0, eth0, eth1, eth2 etc.:

```
IP_AUTODETECTION_METHOD=skip-interface=enp6s0f0,eth.*
IP6_AUTODETECTION_METHOD=skip-interface=enp6s0f0,eth.*
```

#### cidr=CIDR

The `cidr` method will select any IP address from the node that falls within the given CIDRs. For example:

Example:

```
IP_AUTODETECTION_METHOD=cidr=10.0.1.0/24,10.0.2.0/24
IP6_AUTODETECTION_METHOD=cidr=2001:4860::0/64
```

### Node readiness

The `calico/node` container supports an exec readiness endpoint.

To access this endpoint, use the following command.

```bash
docker exec calico-node /bin/calico-node [flag]
```

Substitute `[flag]` with one or more of the following.

- `-bird-ready`
- `-bird6-ready`
- `-felix-ready`

The BIRD readiness endpoint ensures that the BGP mesh is healthy by verifying that all BGP peers are established and
no graceful restart is in progress. If the BIRD readiness check is failing due to unreachable peers that are no longer
in the cluster, see [decommissioning a node]({{site.baseurl}}/maintenance/decommissioning-a-node).


### Setting `CALICO_ROUTER_ID` for IPv6 only system

Setting CALICO_ROUTER_ID to value `hash` will use a hash of the configured nodename for the router ID.  This should only be used in IPv6-only systems with no IPv4 address to use for the router ID.  Since each node chooses its own router ID in isolation, it is possible for two nodes to pick the same ID resulting in a clash.  The probability of such a clash grows with cluster size so this feature should not be used in a large cluster (500+ nodes).

%>

{% endtabs %}


[installation]: {{site.baseurl}}/reference/installation/api
