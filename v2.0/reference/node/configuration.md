---
title: Configuring calico/node
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/node/configuration'
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
| AS | The AS number for this node. When specified, the value is saved in the node resource configuration for this host, overriding any previously configured value. When omitted, if an AS number has been previously configured in the node resource, that AS number is used for the peering.  When omitted, if an AS number has not yet been configured in the node resource, the node will use the global value (managed through `calicoctl config set/get asnumber`). | int | global AS number |
| DATASTORE_TYPE | Type of datastore. | kubernetes, etcdv2 | etcdv2 |
| WAIT_FOR_DATASTORE | Wait for connection to datastore before starting. If a successful connection is not made, node will shutdown. | boolean | false |
| CALICO_LIBNETWORK_ENABLED | Enables running the docker-libnetwork plugin directly in the calico/node container. | boolean | true |
| CALICO_LIBNETWORK_IFPREFIX | Interface prefix to use for the network interface within the Docker containers that have been networked by the Calico driver. | string | cali |
| CALICO_NETWORKING_BACKEND | Describes which BGP networking backend to use| gobgp, bird, none | bird |
| ETCD_ENDPOINTS    | A comma separated list of etcd endpoints (optional, defaults to http://127.0.0.1:2379) | http://etcd1:2379 | |
| ETCD_KEY_FILE     | Path to the etcd key file (optional)       | /etc/calico/key.pem | |
| ETCD_CERT_FILE    | Path to the etcd client cert (optional)    | /etc/calico/cert.pem | |
| ETCD_CA_CERT_FILE | Path to the etcd CA file (optional)        | /etc/calico/ca.pem | |
