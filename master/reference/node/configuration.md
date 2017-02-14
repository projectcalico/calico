---
title: Configuring calico/node
---

The `calico/node` container is primarily configured through environment variables.


## Environment Variables

| Environment | Description                              | Schema | Default |
| ------------- | -------- | ------ | ----- |
| NODENAME | A unique identifier for this host. | string | |
| NO_DEFAULT_POOLS | Prevents Calico from creating a default pool if one does not exist. | string | |
| HOSTNAME [Deprecated] | The Hostname of this host. This is used as a unique identifier for the node. This value is overridden by NODENAME. When omitted, if NODENAME has not been specified, this value defaults to the actual hostname of this host. | string | |
| IP | The IPv4 address to assign this host. When specified, the address is saved in the [node resource configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/node) for this host, overriding any previously configured value. When omitted, if an address **has** been saved in the node resource, then that value will be used. When omitted, if an address **has not** yet been configured in the node resource, the node will auto-detect an IPv4 address and configure the node resource with that address. This autodetection can be forced (even if a value has already been set in the node resource) by setting IP to "autodetect". Doing so will overwrite any value configured in the node resource. | ip address | |
| IP6 | The IPv6 address for Calico will bind to. When specified, the address is saved in the  [node resource configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/node) for this host, overriding any previously configured value. When omitted, if an address has not yet been configured in the node resource, IPv6 routing is not enabled. When omitted, if an IPv6 address has been previously configured in the node resource, IPv6 is enabled using the already configured address. | ipv6 address | |
| IP_AUTODETECT_METHOD| The method to use to autodetect the IPv4 address for this host. This is only used when the IPv4 address is being autodetected. See [IP Autodetection methods](#ip-autodetection-methods) for details of the valid methods. | string | first-found |
| IP6_AUTODETECT_METHOD| The method to use to autodetect the IPv6 address for this host. This is only used when the IPv6 address is being autodetected. See [IP Autodetection methods](#ip-autodetection-methods) for details of the valid methods. | string | first-found |
| AS | The AS number for this node. When specified, the value is saved in the node resource configuration for this host, overriding any previously configured value. When omitted, if an AS number has been previously configured in the node resource, that AS number is used for the peering.  When omitted, if an AS number has not yet been configured in the node resource, the node will use the global value (managed through `calicoctl config set/get asnumber`). | int | global AS number |
| DATASTORE_TYPE | Type of datastore. | kubernetes, etcdv2 | etcdv2 |
| WAIT_FOR_DATASTORE | Wait for connection to datastore before starting. If a successful connection is not made, node will shutdown. | boolean | false |
| CALICO_LIBNETWORK_ENABLED | Enables running the docker-libnetwork plugin directly in the calico/node container. | boolean | true |
| CALICO_LIBNETWORK_IFPREFIX | Interface prefix to use for the network interface within the Docker containers that have been networked by the Calico driver. | string | cali |
| CALICO_NETWORKING_BACKEND | Describes which BGP networking backend to use| gobgp, bird, none | bird |
| CALICO_IPV4POOL_CIDR | The IPv4 Pool to create if none exists at start up. It is invalid to define this variable and NO_DEFAULT_POOLS. | IPv4 CIDR | 192.168.0.0/16 | |
| CALICO_IPV6POOL_CIDR | The IPv6 Pool to create if none exists at start up. It is invalid to define this variable and NO_DEFAULT_POOLS. | IPv6 CIDR | fd80:24e2:f998:72d6::/64 | |
| CALICO_IPIP_ENABLED  | Enable IPIP on any IP Pools created at start up. | string | false | |
| ETCD_ENDPOINTS    | A comma separated list of etcd endpoints (optional, defaults to http://127.0.0.1:2379) | http://etcd1:2379 | |
| ETCD_KEY_FILE     | Path to the etcd key file (optional)       | /etc/calico/key.pem | |
| ETCD_CERT_FILE    | Path to the etcd client cert (optional)    | /etc/calico/cert.pem | |
| ETCD_CA_CERT_FILE | Path to the etcd CA file (optional)        | /etc/calico/ca.pem | |

In addition to the above, `calico/node` also supports [the standard Felix configuration environment variables](../felix/configuration).


### IP Autodetection methods

The following describe the available IP autodetection methods.

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
IP_AUTODETECT_METHOD=first-found
IP6_AUTODETECT_METHOD=first-found
```

#### can-reach=DESTINATION
The `can-reach` method uses your local routing to determine which IP address
will be used to reach the supplied destination.  Both IP addresses and domain
names may be used.

e.g.
```
# Using IP addresses
IP_AUTODETECT_METHOD=can-reach=8.8.8.8
IP6_AUTODETECT_METHOD=can-reach=2001:4860:4860::8888

# Using domain names
IP_AUTODETECT_METHOD=can-reach=www.google.com
IP6_AUTODETECT_METHOD=can-reach=www.google.com
```

#### interface=INTERFACE-REGEX
The `interface` method uses the supplied interface regular expression (golang
syntax) to enumerate matching interfaces and to return the first IP address on
the first matching interface.  The order that both the interfaces
and the IP addresses are listed is system dependent.

e.g.
```
# Valid IP address on interface eth0, eth1, eth2 etc.
IP_AUTODETECT_METHOD=interface=eth.*
IP6_AUTODETECT_METHOD=interface=eth.*
```
