---
title: Configuring calico/node
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/node/configuration'
---

The `calico/node` container is primarily configured through environment variables.


## Environment Variables

| Environment | Description                              | Schema | Default |
| ------------- | -------- | ------ | ----- |
| NODENAME | A unique identifier for this host. | string | |
| NO_DEFAULT_POOLS | Prevents Calico from creating a default pool if one does not exist. | string | |
| HOSTNAME [Deprecated] | The Hostname of this host. This is used as a unique identifier for the node. This value is overridden by NODENAME. When omitted, if NODENAME has not been specified, this value defaults to the actual hostname of this host. | string | |
| IP | The IPv4 address to assign this host. When specified, the address is saved in the [node resource configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/node) for this host, overriding any previously configured value. When omitted, if an address **has** been saved in the node resource, then that value will be used. When omitted, if an address **has not** yet been configured in the node resource, the node will auto-detect an IPv4 address and configure the node resource with that address. This autodetection can be forced (even if a value has already been set in the node resource) by setting IP to "autodetect". Doing so will overwrite any value configured in the node resource. | IPv4 | |
| IP6 | The IPv6 address for Calico will bind to. When specified, the address is saved in the  [node resource configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/node) for this host, overriding any previously configured value. When omitted, if an address has not yet been configured in the node resource, IPv6 routing is not enabled. When omitted, if an IPv6 address has been previously configured in the node resource, IPv6 is enabled using the already configured address. | IPv6 | |
| IP_AUTODETECTION_METHOD| The method to use to autodetect the IPv4 address for this host. This is only used when the IPv4 address is being autodetected. See [IP Autodetection methods](#ip-autodetection-methods) for details of the valid methods. | string | first-found |
| IP6_AUTODETECTION_METHOD| The method to use to autodetect the IPv6 address for this host. This is only used when the IPv6 address is being autodetected. See [IP Autodetection methods](#ip-autodetection-methods) for details of the valid methods. | string | first-found |
| DISABLE_NODE_IP_CHECK| Skips checks for duplicate Node IPs. This can reduce the load on the cluster when a large number of Nodes are restarting. | bool | false |
| AS | The AS number for this node. When specified, the value is saved in the node resource configuration for this host, overriding any previously configured value. When omitted, if an AS number has been previously configured in the node resource, that AS number is used for the peering.  When omitted, if an AS number has not yet been configured in the node resource, the node will use the global value (managed through `calicoctl config set/get asnumber`). | int | |
| DATASTORE_TYPE | Type of datastore. | kubernetes, etcdv2 | etcdv2 |
| WAIT_FOR_DATASTORE | Wait for connection to datastore before starting. If a successful connection is not made, node will shutdown. | boolean | false |
| CALICO_LIBNETWORK_CREATE_PROFILES | Enables creating a Calico profile resource for each Docker network.  When disabled, no profiles will be processed even if manually created. | boolean | true |
| CALICO_LIBNETWORK_LABEL_ENDPOINTS | Enables copying a subset of the Docker container labels for use as Calico labels on workloadendpoints. | boolean | false |
| CALICO_LIBNETWORK_ENABLED | Enables running the docker-libnetwork plugin directly in the calico/node container. | boolean | true |
| CALICO_LIBNETWORK_IFPREFIX | Interface prefix to use for the network interface within the Docker containers that have been networked by the Calico driver. | string | cali |
| CALICO_NETWORKING_BACKEND | Describes which BGP networking backend to use| gobgp, bird, none | bird |
| CALICO_IPV4POOL_CIDR | The IPv4 Pool to create if none exists at start up. It is invalid to define this variable and NO_DEFAULT_POOLS. | IPv4 CIDR | 192.168.0.0/16 |
| CALICO_IPV6POOL_CIDR | The IPv6 Pool to create if none exists at start up. It is invalid to define this variable and NO_DEFAULT_POOLS. | IPv6 CIDR | fd80:24e2:f998:72d6::/64 |
| CALICO_IPV4POOL_IPIP | IPIP Mode to use for the IPv4 POOL created at start up. | off, always, cross-subnet | off |
| CALICO_IPV4POOL_NAT_OUTGOING | Controls NAT Outgoing for the IPv4 Pool created at start up. | boolean | true |
| CALICO_IPV6POOL_NAT_OUTGOING | Controls NAT Outgoing for the IPv6 Pool created at start up. | boolean | false |
| CALICO_STARTUP_LOGLEVEL      | The log severity above which startup calico/node logs are sent to the stdout. | string | ERROR |
| CLUSTER_TYPE | Contains comma delimited list of indicators about this cluster.  e.g. k8s, mesos, kubeadm, canal, bgp | string | |
| ETCD_ENDPOINTS    | A comma separated list of etcd endpoints (optional) | string | http://127.0.0.1:2379 |
| ETCD_KEY_FILE     | Path to the etcd key file, e.g. `/etc/calico/key.pem` (optional)       | string | |
| ETCD_CERT_FILE    | Path to the etcd client cert, e.g. `/etc/calico/cert.pem` (optional)    | string | |
| ETCD_CA_CERT_FILE | Path to the etcd CA file, e.g. `/etc/calico/ca.pem` (optional)        | string | |
| KUBECONFIG | When using the kubernetes datastore, the location of a kubeconfig file to use. | string | |
| K8S_API_ENDPOINT | Location of the Kubernetes API.  Not required if using kubeconfig. | string | |
| K8S_CERT_FILE | Location of a client certificate for accessing the Kubernetes API. | string | |
| K8S_KEY_FILE | Location of a client key for accessing the Kubernetes API. | string | |
| K8S_CA_FILE | Location of a CA for accessing the Kubernetes API. | string | |
| K8S_TOKEN | Token to be used for accessing the Kubernetes API. | string | |

In addition to the above, `calico/node` also supports [the standard Felix configuration environment variables](../felix/configuration).

> Note: When Calico is configured to use the Kubernetes API as the datastore, the environments
> used for BGP configuration are ignored - this includes selection of the node AS number (AS)
> and all of the IP selection options (IP, IP6, IP_AUTODETECTION_METHOD, IP6_AUTODETECTION_METHOD).

### IP Autodetection methods

When Calico is used for routing, each node must be configured with the IPv4
address (and IPv6 address if using IPv6) that would be used to route between
nodes. To eliminate node specific IP address configuration, the calico/node
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

#### can-reach=DESTINATION

The `can-reach` method uses your local routing to determine which IP address
will be used to reach the supplied destination.  Both IP addresses and domain
names may be used.

e.g.

```
# Using IP addresses
IP_AUTODETECTION_METHOD=can-reach=8.8.8.8
IP6_AUTODETECTION_METHOD=can-reach=2001:4860:4860::8888

# Using domain names
IP_AUTODETECTION_METHOD=can-reach=www.google.com
IP6_AUTODETECTION_METHOD=can-reach=www.google.com
```

#### interface=INTERFACE-REGEX

The `interface` method uses the supplied interface regular expression (golang
syntax) to enumerate matching interfaces and to return the first IP address on
the first matching interface.  The order that both the interfaces
and the IP addresses are listed is system dependent.

e.g.

```
# Valid IP address on interface eth0, eth1, eth2 etc.
IP_AUTODETECTION_METHOD=interface=eth.*
IP6_AUTODETECTION_METHOD=interface=eth.*
```
